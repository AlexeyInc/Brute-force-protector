package memorystorage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	bfprotectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
)

var RequestContextWG = &sync.WaitGroup{}

type MemoryStorage struct {
	mutex         *sync.Mutex
	config        bfprotectorconfig.Config
	Bucket        map[string]int
	BlackWhiteIPs map[string][]string
}

var ContextDoneCh = make(chan struct{})

func New(conf bfprotectorconfig.Config) *MemoryStorage {
	return &MemoryStorage{
		config:        conf,
		Bucket:        make(map[string]int),
		BlackWhiteIPs: make(map[string][]string),
		mutex:         new(sync.Mutex),
	}
}

func (ms *MemoryStorage) Close() {
	ms.Bucket = make(map[string]int)
	ms.BlackWhiteIPs = make(map[string][]string)
}

func (ms *MemoryStorage) AddBruteForceLimit(key string, limit int) {
	ms.Bucket[key] = limit
}

func (ms *MemoryStorage) ResetStorage() {
	ms.Bucket = make(map[string]int)
}

func (ms *MemoryStorage) ResetDoneContext() {
	ContextDoneCh = make(chan struct{})
}

func (ms *MemoryStorage) CheckBruteForce(context context.Context,
	key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error,
) {
	ms.mutex.Lock()
	defer RequestContextWG.Done()
	defer ms.mutex.Unlock()

	if _, exists := ms.Bucket[key]; !exists {
		select {
		case <-ContextDoneCh:
			return
		default:
			err <- errors.New("simulate error test")
			close(ContextDoneCh)
			return
		}
	}

	ms.Bucket[key]--
	attempts, exists := ms.Bucket[key]
	if !exists || attempts < 0 {
		select {
		case <-ContextDoneCh:
			return
		default:
			allow <- false
			close(ContextDoneCh)
			return
		}
	}

	select {
	case <-ContextDoneCh:
		return
	default:
		allow <- true
	}
}

func (ms *MemoryStorage) IsReservedIP(ctx context.Context, key, ip string) (bool, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	subnets, exists := ms.BlackWhiteIPs[key]
	if !exists {
		return false, fmt.Errorf("%s", constant.DBSubnetsErr)
	}
	if len(subnets) > 0 {
		for _, cidr := range subnets {
			_, ipv4Net, err := net.ParseCIDR(cidr)
			if err != nil {
				return false, fmt.Errorf("%s: %w", constant.DBRequestErr, err)
			}
			ipv4Addr := net.ParseIP(ip)
			if ipv4Net.Contains(ipv4Addr) {
				finalizeRequest()
				return true, nil
			}
		}
	}
	return false, nil
}

func finalizeRequest() {
	for i := 0; i < constant.AttackTypesCount; i++ {
		RequestContextWG.Done()
	}
}

func (ms *MemoryStorage) Seed(context context.Context, keys []string, data [][]string) error {
	if len(keys) != len(data) {
		return errors.New("amount of keys not equal to values")
	}
	for i := 0; i < len(keys); i++ {
		ms.BlackWhiteIPs[keys[i]] = data[i]
	}
	return nil
}

func (ms *MemoryStorage) ResetBucket(context context.Context, key string) (err error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	if strings.HasSuffix(key, "_Login") {
		ms.Bucket[key] = ms.config.AttemptsLimit.LoginRequestsMinute
	}
	if net.ParseIP(key) != nil {
		ms.Bucket[key] = ms.config.AttemptsLimit.IPRequestsMinute
	}
	ms.ResetDoneContext()
	return
}

func (ms *MemoryStorage) AddToReservedSubnets(context context.Context, key string, subnet string) (err error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.BlackWhiteIPs[key] = append(ms.BlackWhiteIPs[key], subnet)
	return
}

func (ms *MemoryStorage) RemoveFromReservedSubnets(context context.Context, key string, subnet string) (err error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ips, ok := ms.BlackWhiteIPs[key]
	if !ok {
		return
	}
	indx := -1
	for i, v := range ips {
		if v == subnet {
			indx = i
			break
		}
	}
	if indx == -1 {
		return
	}
	ips[indx] = ips[len(ips)-1]
	ms.BlackWhiteIPs[key] = ips[:len(ips)-1]
	return
}

func (ms *MemoryStorage) GetReservedSubnets(context context.Context, key string) ([]string, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ips, ok := ms.BlackWhiteIPs[key]
	if !ok {
		return nil, fmt.Errorf("key not exist")
	}
	return ips, nil
}
