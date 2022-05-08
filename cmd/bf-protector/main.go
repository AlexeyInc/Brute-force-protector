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
	"github.com/AlexeyInc/Brute-force-protector/internal/logger"
	grpcserver "github.com/AlexeyInc/Brute-force-protector/internal/server"
	redistorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/redis"
	convert "github.com/AlexeyInc/Brute-force-protector/util"
)

var configFile, logFile string

func init() {
	flag.StringVar(&configFile, "config", "../../configs/bf-protector_config.toml", "Path to configuration file")
	flag.StringVar(&logFile, "log", "../../log/logs.log", "Path to log file")
}

func main() {
	flag.Parse()

	config, err := protectorconfig.NewConfig(configFile)
	failOnError(err, constant.ReadConfigErr)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	zapLogg := logger.New(logFile)
	defer zapLogg.ZapLogger.Sync()

	storage := redistorage.New(config, zapLogg)
	if err := storage.Connect(ctx); err != nil {
		zapLogg.Info(fmt.Sprintf("%s: %s", constant.DBConnectionErr, err.Error()))
		cancel()
		return
	}
	zapLogg.Info("Successfully connected to redis database!")
	defer storage.Close()

	err = seedDatabase(ctx, storage)
	if err != nil {
		zapLogg.Info(fmt.Sprintf("%s: %s", constant.DatabaseSeedErr, err.Error()))
		cancel()
		return
	}
	protector := protectorapp.New(config, storage)

	zapLogg.Info("Starting gRPC server...")

	go grpcserver.RunGRPCServer(ctx, config, protector, zapLogg)

	<-ctx.Done()

	zapLogg.Info("All servers are stopped...")
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
