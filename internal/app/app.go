package protectorapp

import (
	"context"
	"errors"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	"google.golang.org/grpc/peer"
)

const (
	_whiteListIPText        = "sender IP is in whitelist"
	_blackListIPText        = "sender IP is in black list"
	_limitExceededText      = "limit of authorization attempts exceeded"
	_readPeerFromContextErr = "can't read peer info from context"
	_bruteForceErr          = "error during brute force check"
)

type App struct {
	api.UnimplementedAuthorizationServiceServer

	storage Storage
	config  protectorconfig.Config
}

type Storage interface {
	CheckBruteForce(context context.Context, key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error)
	CheckWhiteList(ctx context.Context, ip string) bool
	CheckBlackList(ctx context.Context, ip string) bool
}

func New(config protectorconfig.Config, storage Storage) *App {
	return &App{
		config:  config,
		storage: storage,
	}
}

func (a *App) Authorization(ctx context.Context, login *api.Login) (*api.StatusResponse, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return &api.StatusResponse{
			Success: false,
			Data:    _readPeerFromContextErr,
		}, errors.New(_readPeerFromContextErr)
	}
	ip := p.Addr.String()

	if exists := a.storage.CheckWhiteList(ctx, login.Login); exists {
		return &api.StatusResponse{
			Success: true,
			Data:    _whiteListIPText,
		}, nil
	}
	if exists := a.storage.CheckBlackList(ctx, login.Login); exists {
		return &api.StatusResponse{
			Success: false,
			Data:    _blackListIPText,
		}, nil
	}

	ctx, cancel := context.WithCancel(ctx)

	allowAttemptCh := make(chan bool)
	defer close(allowAttemptCh)
	errCh := make(chan error)
	defer close(errCh)

	go a.storage.CheckBruteForce(ctx, login.Login, a.config.AttemptsLimit.LoginFreqMin, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, login.Password, a.config.AttemptsLimit.PasswordFreqMin, allowAttemptCh, errCh)
	go a.storage.CheckBruteForce(ctx, ip, a.config.AttemptsLimit.IPFreqMin, allowAttemptCh, errCh)

	count := 0
	for {
		select {
		case err := <-errCh:
			cancel()
			return &api.StatusResponse{
				Success: false,
				Data:    _bruteForceErr,
			}, err
		default:
		}

		res := <-allowAttemptCh
		if !res {
			cancel()
			return &api.StatusResponse{
				Success: false,
				Data:    _limitExceededText,
			}, nil
		}

		count++
		if count == 3 {
			break
		}
	}

	cancel()

	return &api.StatusResponse{
		Success: true,
	}, nil
}
