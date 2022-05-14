package protectorapp

import (
	"context"
	"fmt"
	"net"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	api "github.com/AlexeyInc/Brute-force-protector/pkg/grpc"
)

type App struct {
	api.UnimplementedBruteForceProtectorServiceServer

	storage Storage
	config  protectorconfig.Config
}

type Storage interface {
	CheckBruteForce(context context.Context, key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error)
	ResetBucket(context context.Context, key string) error
	AddToReservedSubnets(context context.Context, key, ipNet string) error
	RemoveFromReservedSubnets(context context.Context, key, ipNet string) error
	IsReservedIP(ctx context.Context, key, ip string) (bool, error)
	GetReservedSubnets(context context.Context, key string) ([]string, error)
}

func New(config protectorconfig.Config, storage Storage) *App {
	return &App{
		config:  config,
		storage: storage,
	}
}

func (a *App) Authorization(ctx context.Context, login *api.AuthRequest) (*api.StatusResponse, error) {
	if !login.IsValid() {
		return responseModel(false, constant.ModelVlidationErr, nil)
	}

	isWhiteListIP, err := a.storage.IsReservedIP(ctx, constant.WhiteSubnetsKey, login.Ip)
	if err != nil {
		return responseModel(false, "", err)
	}
	if isWhiteListIP {
		return responseModel(true, constant.WhiteListIPText, nil)
	}
	isBlackListIP, err := a.storage.IsReservedIP(ctx, constant.BlackSubnetsKey, login.Ip)
	if err != nil {
		return responseModel(false, "", err)
	}
	if isBlackListIP {
		return responseModel(false, constant.BlackListIPText, nil)
	}

	ctx, cancel := context.WithCancel(ctx)

	allowAttemptCh := make(chan bool)
	defer close(allowAttemptCh)

	errCh := make(chan error)
	defer close(errCh)

	go a.storage.CheckBruteForce(ctx,
		login.GetLogin(), a.config.AttemptsLimit.LoginRequestsMinute, allowAttemptCh, errCh,
	)
	go a.storage.CheckBruteForce(ctx,
		login.GetPassword(), a.config.AttemptsLimit.PasswordRequestsMinute, allowAttemptCh, errCh,
	)
	go a.storage.CheckBruteForce(ctx,
		login.GetIp(), a.config.AttemptsLimit.IPRequestsMinute, allowAttemptCh, errCh,
	)

	passedChecks := 0
	for {
		select {
		case err := <-errCh:
			cancel()
			err = fmt.Errorf("%s: %w", constant.BruteForceCheckErr, err)
			return responseModel(false, "", err)
		default:
		}

		select {
		case err := <-errCh:
			cancel()
			err = fmt.Errorf("%s: %w", constant.BruteForceCheckErr, err)
			return responseModel(false, "", err)
		case res := <-allowAttemptCh:
			if !res {
				cancel()
				return responseModel(false, constant.LimitExceededText, nil)
			}
		}
		passedChecks++
		if passedChecks == constant.AttackTypesCount {
			break
		}
	}
	cancel()
	return responseModel(true, constant.AuthAllowedText, nil)
}

func (a *App) ResetBuckets(ctx context.Context, bucket *api.ResetBucketRequest) (*api.StatusResponse, error) {
	if bucket.GetIp() != "" {
		if err := a.storage.ResetBucket(ctx, bucket.Ip); err != nil {
			return responseModel(false, "", fmt.Errorf("%s: %w", constant.ResetBucketErr, err))
		}
	}
	if bucket.GetLogin() != "" {
		if err := a.storage.ResetBucket(ctx, bucket.Login); err != nil {
			return responseModel(false, "", fmt.Errorf("%s: %w", constant.ResetBucketErr, err))
		}
	}
	return responseModel(true, constant.BucketResetText, nil)
}

func (a *App) AddWhiteListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	ipv4Net, err := getIPNetFromCIDR(subnet.Cidr)
	if err != nil {
		return responseModel(false, "", fmt.Errorf("%s: %w", constant.SubnetParseErr, err))
	}
	resp, err := a.createRespIfAlreadyUsed(ctx, constant.WhiteSubnetsKey, ipv4Net)
	if resp != nil {
		return resp, err
	}
	if err = a.storage.AddToReservedSubnets(ctx, constant.WhiteSubnetsKey, ipv4Net.String()); err != nil {
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.WhiteSubnetAddedText, nil)
}

func (a *App) DeleteWhiteListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	ipv4Net, err := getIPNetFromCIDR(subnet.Cidr)
	if err != nil {
		return responseModel(false, "", fmt.Errorf("%s: %w", constant.SubnetParseErr, err))
	}
	if err = a.storage.RemoveFromReservedSubnets(ctx, constant.WhiteSubnetsKey, ipv4Net.String()); err != nil {
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.WhiteSubnetRemovedText, nil)
}

func (a *App) AddBlackListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	ipv4Net, err := getIPNetFromCIDR(subnet.Cidr)
	if err != nil {
		return responseModel(false, "", fmt.Errorf("%s: %w", constant.SubnetParseErr, err))
	}
	resp, err := a.createRespIfAlreadyUsed(ctx, constant.BlackSubnetsKey, ipv4Net)
	if resp != nil {
		return resp, err
	}
	if err := a.storage.AddToReservedSubnets(ctx, constant.BlackSubnetsKey, ipv4Net.String()); err != nil {
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.BlackSubnetAddedText, nil)
}

func (a *App) DeleteBlackListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	ipv4Net, err := getIPNetFromCIDR(subnet.Cidr)
	if err != nil {
		return responseModel(false, "", fmt.Errorf("%s: %w", constant.SubnetParseErr, err))
	}
	if err := a.storage.RemoveFromReservedSubnets(ctx, constant.BlackSubnetsKey, ipv4Net.String()); err != nil {
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.BlackSubnetRemovedText, nil)
}

func (a *App) createRespIfAlreadyUsed(ctx context.Context,
	key string, inputSubnet *net.IPNet,
) (*api.StatusResponse, error) {
	var whiteSubnets, blackSubnets []string
	var err error
	if whiteSubnets, err = a.storage.GetReservedSubnets(ctx, constant.WhiteSubnetsKey); err != nil {
		return responseModel(false, "", err)
	}
	if blackSubnets, err = a.storage.GetReservedSubnets(ctx, constant.BlackSubnetsKey); err != nil {
		return responseModel(false, "", err)
	}

	switch key {
	case constant.WhiteSubnetsKey:
		if isSubnetsContain(whiteSubnets, inputSubnet) {
			return responseModel(false, constant.ExistInWhiteListErr, nil)
		}
		if isSubnetsIntercept(blackSubnets, inputSubnet) {
			return responseModel(false, constant.InterceptionBlackListErr, nil)
		}
	case constant.BlackSubnetsKey:
		if isSubnetsContain(blackSubnets, inputSubnet) {
			return responseModel(false, constant.ExistInBlackListErr, nil)
		}
		if isSubnetsIntercept(whiteSubnets, inputSubnet) {
			return responseModel(false, constant.InterceptionWhiteListErr, nil)
		}
	default:
		return responseModel(false, "", fmt.Errorf("key %s not exist", key))
	}
	return nil, nil
}

func isSubnetsContain(subnets []string, subnetToSearch *net.IPNet) bool {
	for _, s := range subnets {
		if s == subnetToSearch.String() {
			return true
		}
	}
	return false
}

func isSubnetsIntercept(subnets []string, subnetToCompare *net.IPNet) bool {
	for _, s := range subnets {
		_, subnet, _ := net.ParseCIDR(s)
		if netIntersect(subnet, subnetToCompare) {
			return true
		}
	}
	return false
}

func netIntersect(n1, n2 *net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

func getIPNetFromCIDR(cidr string) (*net.IPNet, error) {
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipv4Net, nil
}

func responseModel(succes bool, msg string, err error) (*api.StatusResponse, error) {
	return &api.StatusResponse{
		Success: succes,
		Msg:     msg,
	}, err
}
