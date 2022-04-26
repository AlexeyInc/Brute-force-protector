package protectorapp

import (
	"context"
	"fmt"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
)

type App struct {
	api.UnimplementedBruteForceProtectorServiceServer

	storage Storage
	config  protectorconfig.Config
}

type Storage interface {
	CheckBruteForce(context context.Context, key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error)
	IsReservedIP(context context.Context, key, ip string) bool
	ResetBucket(context context.Context, key string) error
	AddToReservedIPs(context context.Context, key, ip string) error
	RemoveFromReservedIPs(context context.Context, key, ip string) error
}

func New(config protectorconfig.Config, storage Storage) *App {
	return &App{
		config:  config,
		storage: storage,
	}
}

// TODO: add unit test for check empty request model
func (a *App) Authorization(ctx context.Context, login *api.AuthRequest) (*api.StatusResponse, error) {
	if !login.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}

	if exists := a.storage.IsReservedIP(ctx, constant.WhiteIPsKey, login.Ip); exists {
		return responseModel(true, constant.WhiteListIpText, nil)
	}
	if exists := a.storage.IsReservedIP(ctx, constant.BlackIPsKey, login.Ip); exists {
		return responseModel(false, constant.BlackListIpText, nil)
	}

	ctx, cancel := context.WithCancel(ctx)
	allowAttemptCh := make(chan bool)
	defer close(allowAttemptCh)
	errCh := make(chan error)
	defer close(errCh)

	go a.storage.CheckBruteForce(ctx, login.GetLogin(), a.config.AttemptsLimit.LoginRequestsMinute, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, login.GetPassword(), a.config.AttemptsLimit.PasswordRequestsMinute, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, login.GetIp(), a.config.AttemptsLimit.IpRequestsMinute, allowAttemptCh, errCh)

	passedChecks := 0
	for {
		select {
		case err := <-errCh:
			cancel()
			err = fmt.Errorf("%s: %s", constant.BruteForceCheckErr, err)
			return responseModel(false, "", err)
		default:
		}

		select {
		case err := <-errCh:
			cancel()
			err = fmt.Errorf("%s: %s", constant.BruteForceCheckErr, err)
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
	if !bucket.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	err := a.storage.ResetBucket(ctx, bucket.Ip)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.ResetBucketErr, err)
		return responseModel(false, "", err)
	}
	err = a.storage.ResetBucket(ctx, bucket.Login)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.ResetBucketErr, err)
		return responseModel(false, "", err)
	}

	return responseModel(true, constant.BucketResetText, nil)
}

func (a *App) AddWhiteListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	err := a.storage.AddToReservedIPs(ctx, constant.WhiteIPsKey, subnet.Ip)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.WhiteListAddErr, err)
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.WhiteIpAddedText, nil)
}

func (a *App) DeleteWhiteListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	err := a.storage.RemoveFromReservedIPs(ctx, constant.WhiteIPsKey, subnet.Ip)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.BlackListRemoveErr, err)
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.WhiteIpAddedText, nil)
}

func (a *App) AddBlackListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	err := a.storage.AddToReservedIPs(ctx, constant.BlackIPsKey, subnet.Ip)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.BlackListAddErr, err)
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.BlackListIpText, nil)
}

func (a *App) DeleteBlackListIP(ctx context.Context, subnet *api.SubnetRequest) (*api.StatusResponse, error) {
	if !subnet.IsValid() {
		return responseModel(false, "", fmt.Errorf(constant.ModelVlidationErr))
	}
	err := a.storage.RemoveFromReservedIPs(ctx, constant.BlackIPsKey, subnet.Ip)
	if err != nil {
		err = fmt.Errorf("%s: %s", constant.BlackListRemoveErr, err)
		return responseModel(false, "", err)
	}
	return responseModel(true, constant.BlackIpRemovedText, nil)
}

func responseModel(succes bool, msg string, err error) (*api.StatusResponse, error) {
	return &api.StatusResponse{
		Success: succes,
		Msg:     msg,
	}, err
}
