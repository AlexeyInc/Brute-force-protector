package redisstorage

import (
	"fmt"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"golang.org/x/net/context"
)

const (
	_whiteListIPs = "whitelistIPs"
	_blackListIPs = "blacklistIPs"
)

type Storage struct {
	rdb     *redis.Client
	limiter *redis_rate.Limiter
	Source  string
}

func New(pc protectorconfig.Config) *Storage {
	return &Storage{
		Source: pc.Storage.Source,
	}
}

func (s *Storage) Connect(ctx context.Context) error {
	rdb := redis.NewClient(&redis.Options{
		Addr: s.Source,
		// TODO: Add password
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("cannot ping redis: %w", err)
	}
	s.rdb = rdb
	s.limiter = redis_rate.NewLimiter(s.rdb)

	return nil
}

func (s *Storage) Close(ctx context.Context) error {
	return s.rdb.Close()
}

func (s *Storage) Seed(ctx context.Context) error {
	// TODO: load whiteblack lists from file
	err := s.rdb.LPush(ctx, _whiteListIPs, "testWhiteList_1", "testWhiteList_2").Err()
	if err != nil {
		return err
	}
	err = s.rdb.LPush(ctx, _blackListIPs, "testBlackList_1", "testBlackList_2").Err()
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) CheckBruteForce(ctx context.Context, key string, requestLimitPerMinutes int, allowCh chan<- bool, errCh chan<- error) {
	res, err := s.limiter.Allow(ctx, key, redis_rate.PerMinute(requestLimitPerMinutes))
	if err != nil { //TODO: add test which checks scenario with errors
		select {
		case <-ctx.Done():
			return
		default:
			fmt.Println("check err:", err)
			errCh <- err
			return
		}
	}

	fmt.Println("allowed:", res.Allowed > 0, "; "+key+" attempts remaining:", res.Remaining)
	if res.Allowed == 0 {
		select {
		case <-ctx.Done():
			return
		default:
			allowCh <- false
			return
		}

	}
	select {
	case <-ctx.Done():
		return
	default:
		allowCh <- true
	}
}

func (s *Storage) CheckWhiteList(ctx context.Context, ip string) bool {
	whiteIPs, err := s.rdb.LRange(ctx, _whiteListIPs, 0, -1).Result()
	if err != nil {
		fmt.Println("failed during check in white list:", err)
		return false
	}
	for _, whiteIP := range whiteIPs {
		if whiteIP == ip {
			return true
		}
	}
	return false
}

func (s *Storage) CheckBlackList(ctx context.Context, ip string) bool {
	whiteIPs, err := s.rdb.LRange(ctx, _blackListIPs, 0, -1).Result()
	if err != nil {
		fmt.Println("failed during check in black list:", err)
		return false
	}
	for _, blackIP := range whiteIPs {
		if blackIP == ip {
			return true
		}
	}
	return false
}
