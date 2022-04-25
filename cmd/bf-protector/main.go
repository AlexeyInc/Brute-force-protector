package main

import (
	"bytes"
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
	redisstorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/redis"
)

var configFile, whiteBlackListFile string // , logFile string

func init() {
	flag.StringVar(&configFile, "config", "../../configs/bf-protector_config.toml", "Path to configuration file")
	flag.StringVar(&whiteBlackListFile, "lists", "../../assets/", "Path to white/black list files folder")
	//flag.StringVar(&logFile, "log", "../../log/logs.log", "Path to log file")
}

func main() {
	bCh := make(chan int, 1)

	val := <-bCh

	fmt.Println(val)
	flag.Parse()

	config, err := protectorconfig.NewConfig(configFile)
	if err != nil {
		log.Fatal("can't read config file: " + err.Error())
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

	err = storage.Seed(ctx, constant.WhiteIPsKey, byteRowsToStrings(embed.ReadWhiteList()))
	if err != nil {
		fmt.Println("can't seed database." + err.Error())
		cancel()
		return
	}
	err = storage.Seed(ctx, constant.BlackIPsKey, byteRowsToStrings(embed.ReadBlackList()))
	if err != nil {
		fmt.Println("can't seed database." + err.Error())
		cancel()
		return
	}

	protector := protectorapp.New(config, storage)

	go grpcserver.RunGRPCServer(ctx, config, protector)

	<-ctx.Done()

	fmt.Println("\nAll servers are stopped...")
}

func byteRowsToStrings(fileData []byte) (result []string) {
	rows := bytes.Split(fileData, []byte{'\n'})
	for _, w := range rows {
		result = append(result, string(w))
	}
	return
}
