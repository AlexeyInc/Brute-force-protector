package redistorage

import (
	"errors"
	"fmt"
	"net"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"golang.org/x/net/context"
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

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		return fmt.Errorf("cannot ping redis: %w", err)
	}
	s.rdb = rdb
	s.limiter = redis_rate.NewLimiter(s.rdb)

	return nil
}

func (s *Storage) Close(ctx context.Context) error {
	return s.rdb.Close()
}

func (s *Storage) Seed(ctx context.Context, keys []string, values [][]string) error {
	if len(keys) != len(values) {
		return errors.New(constant.DatabaseSeedErr)
	}
	for i := 0; i < len(keys); i++ {
		err := s.rdb.LPush(ctx, keys[i], values[i]).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) CheckBruteForce(ctx context.Context,
	key string, requestLimitPerMinutes int, allowCh chan<- bool, errCh chan<- error,
) {
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

func (s *Storage) IsReservedIP(ctx context.Context, key, ip string) (bool, error) {
	subnets, err := s.rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return false, fmt.Errorf("%s: %w", constant.DBSubnetsErr, err)
	}
	if len(subnets) > 0 {
		for _, cidr := range subnets {
			_, ipv4Net, err := net.ParseCIDR(cidr)
			if err != nil {
				return false, fmt.Errorf("%s: %w", constant.DBRequestErr, err)
			}
			ipv4Addr := net.ParseIP(ip)
			if ipv4Net.Contains(ipv4Addr) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Storage) ResetBucket(ctx context.Context, key string) error {
	fmt.Println("Reset for key: ", key)
	return s.limiter.Reset(ctx, key)
}

// TODO: add integration test on dublication...
func (s *Storage) AddToReservedSubnets(context context.Context, key, ipNet string) error {
	reservedIPNets, err := s.rdb.LRange(context, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("%s: %w", constant.DBReserveSubnetErr, err)
	}
	for _, v := range reservedIPNets {
		if v == ipNet {
			return fmt.Errorf("IP: %s already reserved", ipNet)
		}
	}
	return s.rdb.RPush(context, key, ipNet).Err()
}

func (s *Storage) RemoveFromReservedSubnets(context context.Context, key, ipNet string) error {
	reservedIPNets, err := s.rdb.LRange(context, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("%s: %w", constant.DBReserveSubnetErr, err)
	}
	ipIndex := -1
	for i, v := range reservedIPNets {
		if v == ipNet {
			ipIndex = i
			break
		}
	}
	if ipIndex == -1 {
		return fmt.Errorf("IP: %s not reserved", ipNet)
	}
	return s.rdb.LRem(context, key, 0, ipNet).Err()
}
