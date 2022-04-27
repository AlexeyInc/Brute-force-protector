package redistorage

import (
	"errors"
	"fmt"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"golang.org/x/net/context"
)

const (
	_seedDataErr      = "amount of keys not equal to values"
	_reserveFailedErr = "failed to reserve IP"
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

// TODO: take seed func from memory db
// func (s *Storage) Seed(ctx context.Context, key string, data []string) error {
// 	err := s.rdb.LPush(ctx, key, data).Err()
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

func (s *Storage) Seed(ctx context.Context, keys []string, values [][]string) error {
	if len(keys) != len(values) {
		return errors.New(_seedDataErr)
	}
	for i := 0; i < len(keys); i++ {
		err := s.rdb.LPush(ctx, keys[i], values[i]).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) CheckBruteForce(ctx context.Context, key string, requestLimitPerMinutes int, allowCh chan<- bool, errCh chan<- error) {
	res, err := s.limiter.Allow(ctx, key, redis_rate.PerMinute(requestLimitPerMinutes))
	if err != nil {
		select {
		case <-ctx.Done():
			return
		default:
			fmt.Println("check err:", err)
			errCh <- err
			return
		}
	}

	fmt.Println("allowed:", res.Allowed > 0, "(For", key, "remain", res.Remaining, "attempts)")
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
	default:
		allowCh <- true
	}
}

// TODO add error in return param
func (s *Storage) IsReservedIP(ctx context.Context, key string, senderIP string) bool {
	whiteBlackIPs, err := s.rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		fmt.Println("failed during check in "+key+":", err)
		return false
	}
	for _, ip := range whiteBlackIPs {
		if ip == senderIP {
			return true
		}
	}
	return false
}

func (s *Storage) ResetBucket(ctx context.Context, key string) error {
	fmt.Println("Reset for key: ", key)
	return s.limiter.Reset(ctx, key)
}

// TODO: add integration test on dublication
func (s *Storage) AddToReservedIPs(context context.Context, key, ip string) error {
	reservedIPs, err := s.rdb.LRange(context, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("%s: %s", _reserveFailedErr, err)
	}
	for _, v := range reservedIPs {
		if v == ip {
			return fmt.Errorf("IP: %s already reserved", ip)
		}
	}
	return s.rdb.RPush(context, key, ip).Err()
}

func (s *Storage) RemoveFromReservedIPs(context context.Context, key, ip string) error {
	reservedIPs, err := s.rdb.LRange(context, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("%s: %s", _reserveFailedErr, err)
	}
	ipIndex := -1
	for i, v := range reservedIPs {
		if v == ip {
			ipIndex = i
			break
		}
	}
	if ipIndex == -1 {
		return fmt.Errorf("IP: %s not reserved", ip)
	}
	return s.rdb.LRem(context, key, 0, ip).Err()
}
