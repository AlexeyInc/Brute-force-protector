package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	redisstorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/redis"

	protectorapp "github.com/AlexeyInc/Brute-force-protector/internal/app"
	grpcserver "github.com/AlexeyInc/Brute-force-protector/internal/server"
)

// del
type Author struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

var configFile, logFile string

func init() {
	flag.StringVar(&configFile, "config", "../../configs/bf-protector_config.toml", "Path to configuration file")
	//flag.StringVar(&logFile, "log", "../../log/logs.log", "Path to log file")
}

func main() {
	flag.Parse()

	config, err := protectorconfig.NewConfig(configFile)
	if err != nil {
		log.Println("can't read config file: " + err.Error())
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	storage := redisstorage.New(config)
	if err := storage.Connect(ctx); err != nil {
		fmt.Println("connection to database failed. " + err.Error())
		cancel()
		return
	}
	fmt.Println("Successfully connected to redis database...")
	defer storage.Close(ctx)
	storage.Seed(ctx)

	protector := protectorapp.New(config, storage)

	go grpcserver.RunGRPCServer(ctx, config, protector)

	<-ctx.Done()

	fmt.Println("\nAll servers are stopped...")
}

func ExampleNewLimiter() {
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	for i := 0; i < 5; i++ {
		_ = rdb.FlushDB(ctx).Err()
	}

	limiter := redis_rate.NewLimiter(rdb)
	res, err := limiter.Allow(ctx, "project:123", redis_rate.PerMinute(5))
	if err != nil {
		panic(err)
	}
	fmt.Println("allowed", res.Allowed, "remaining", res.Remaining)
	// Output: allowed 1 remaining 9

	err = rdb.Set(ctx, "project:123", "Elliot", 0).Err()
	// if there has been an error setting the value
	// handle the error
	if err != nil {
		fmt.Println(err)
	}

	res, err = limiter.Allow(ctx, "project:123", redis_rate.PerMinute(5))
	if err != nil {
		panic(err)
	}
	fmt.Println("allowed", res.Allowed, "remaining", res.Remaining)

	// fmt.Println("allowed", res.Allowed, "remaining", res.Remaining)

	json, err := json.Marshal(Author{Name: "Elliot", Age: 25})
	if err != nil {
		fmt.Println(err)
	}

	err = rdb.Set(ctx, "project:123", json, 0).Err()
	if err != nil {
		fmt.Println(err)
	}
	val, err := rdb.Get(ctx, "project:123").Result()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(val)

	res, err = limiter.Allow(ctx, "project:123", redis_rate.PerMinute(5))
	if err != nil {
		panic(err)
	}

	fmt.Println("allowed", res.Allowed, "remaining", res.Remaining)

}
