package memorystorage

import (
	"context"
	"errors"
	"sync"
)

var RequestContextWG = &sync.WaitGroup{}

type MemoryStorage struct {
	mutex *sync.Mutex

	Data          map[string]int
	BlackWhiteIPs map[string][]string
}

var ContextDoneCh = make(chan struct{})

//TODO: upload from assets seed

func New() *MemoryStorage {
	return &MemoryStorage{
		Data:          make(map[string]int),
		BlackWhiteIPs: make(map[string][]string),
		mutex:         new(sync.Mutex),
	}
}

func (ms *MemoryStorage) Close() {
	ms.Data = make(map[string]int)
	ms.BlackWhiteIPs = make(map[string][]string)
}

func (ms *MemoryStorage) AddBruteForceLimit(key string, limit int) {
	ms.Data[key] = limit
}

func (ms *MemoryStorage) ResetStorage() {
	ms.Data = make(map[string]int)
	ContextDoneCh = make(chan struct{})
}

func (ms *MemoryStorage) CheckBruteForce(context context.Context, key string, requestLimitPerMinutes int, allow chan<- bool, err chan<- error) {
	ms.mutex.Lock()
	defer RequestContextWG.Done()
	defer ms.mutex.Unlock()

	_, exists := ms.Data[key]
	if !exists {
		select {
		case <-ContextDoneCh:
			return
		default:
			err <- errors.New("simulate error test")
			close(ContextDoneCh)
			return
		}
	}

	ms.Data[key]--
	attempts, exists := ms.Data[key]
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

func (ms *MemoryStorage) CheckBlackWhiteIPs(ctx context.Context, key string, senderIP string) bool {
	ips, exists := ms.BlackWhiteIPs[key]
	if !exists {
		return false
	}
	for _, ip := range ips {
		if ip == senderIP {
			return true
		}
	}
	return false
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
