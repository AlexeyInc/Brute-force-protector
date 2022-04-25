package protectorapp

import (
	"context"
	"errors"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	"google.golang.org/grpc/peer"
)

const (
	_whiteListIPText    = "sender IP is in whitelist"
	_blackListIPText    = "sender IP is in black list"
	_authAllowed        = "authorization allowed"
	_limitExceededText  = "limit of authorization attempts exceeded"
	_readPeerFromCtxErr = "can't read peer info from context"
	_bruteForceCheckErr = "error during brute force check"
	_failedParseCxtErr  = "failed get IP from context"
)

type App struct {
	api.UnimplementedAuthorizationServiceServer

	storage Storage
	config  protectorconfig.Config
	// for unit tests
	getIPFromContext func(context.Context) (string, error)
}

type Storage interface {
	CheckBruteForce(context context.Context, key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error)
	CheckBlackWhiteIPs(ctx context.Context, key string, senderIP string) bool
}

func New(config protectorconfig.Config, storage Storage) *App {
	return &App{
		config:           config,
		storage:          storage,
		getIPFromContext: getIPFromContext,
	}
}

func (a *App) Authorization(ctx context.Context, login *api.Login) (*api.StatusResponse, error) {
	senderIP, err := a.getIPFromContext(ctx)
	if err != nil {
		return reponseModel(false, _failedParseCxtErr, err)
	}

	if exists := a.storage.CheckBlackWhiteIPs(ctx, constant.WhiteIPsKey, senderIP); exists {
		return reponseModel(true, _whiteListIPText, nil)
	}
	if exists := a.storage.CheckBlackWhiteIPs(ctx, constant.BlackIPsKey, senderIP); exists {
		return reponseModel(false, _blackListIPText, nil)
	}

	ctx, cancel := context.WithCancel(ctx)

	allowAttemptCh := make(chan bool)
	defer close(allowAttemptCh)
	errCh := make(chan error)
	defer close(errCh)

	go a.storage.CheckBruteForce(ctx, login.Login, a.config.AttemptsLimit.LoginRequestsMinute, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, login.Password, a.config.AttemptsLimit.PasswordRequestsMinute, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, senderIP, a.config.AttemptsLimit.IpRequestsMinute, allowAttemptCh, errCh)

	passedChecks := 0
	for {
		select {
		case err := <-errCh:
			cancel()
			return reponseModel(false, _bruteForceCheckErr, err)
		default:
		}

		select {
		case err := <-errCh:
			cancel()
			return reponseModel(false, _bruteForceCheckErr, err)
		case res := <-allowAttemptCh:
			if !res {
				cancel()
				return reponseModel(false, _limitExceededText, nil)
			}
		}

		passedChecks++
		if passedChecks == constant.AttackTypesCount {
			break
		}
	}
	cancel()
	return reponseModel(true, _authAllowed, nil)
}

func getIPFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New(_readPeerFromCtxErr)
	}
	return p.Addr.String(), nil
}

func reponseModel(succes bool, msg string, err error) (*api.StatusResponse, error) {
	return &api.StatusResponse{
		Success: succes,
		Msg:     msg,
	}, err
}
