package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	embed "github.com/AlexeyInc/Brute-force-protector/assets"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	protectorapp "github.com/AlexeyInc/Brute-force-protector/internal/app"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	grpcserver "github.com/AlexeyInc/Brute-force-protector/internal/server"
	redistorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/redis"
	convert "github.com/AlexeyInc/Brute-force-protector/util"
)

var configFile, whiteBlackListFile string // , logFile string

func init() {
	flag.StringVar(&configFile, "config", "../../configs/bf-protector_config.toml", "Path to configuration file")
	flag.StringVar(&whiteBlackListFile, "lists", "../../assets/", "Path to white/black list files folder")
	// flag.StringVar(&logFile, "log", "../../log/logs.log", "Path to log file")
}

func main() {
	flag.Parse()

	config, err := protectorconfig.NewConfig(configFile)
	failOnError(err, constant.ReadConfigErr)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	storage := redistorage.New(config)
	if err := storage.Connect(ctx); err != nil {
		fmt.Println(constant.DBConnectionErr, err.Error())
		cancel()
		return
	}
	fmt.Println("Successfully connected to redis database!")
	defer storage.Close(ctx)

	err = seedDatabase(ctx, storage)
	if err != nil {
		fmt.Println(constant.DatabaseSeedErr, err.Error())
		cancel()
		return
	}

	protector := protectorapp.New(config, storage)

	go grpcserver.RunGRPCServer(ctx, config, protector)

	<-ctx.Done()

	fmt.Println("\nAll servers are stopped...")
}

func seedDatabase(ctx context.Context, storage *redistorage.Storage) error {
	return storage.Seed(ctx,
		[]string{
			constant.WhiteSubnetsKey,
			constant.BlackSubnetsKey,
		},
		[][]string{
			convert.ByteRowsToStrings(embed.ReadWhiteList()),
			convert.ByteRowsToStrings(embed.ReadBlackList()),
		},
	)
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
