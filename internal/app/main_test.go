package protectorapp

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	memorystorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/memory"
)

var (
	configFile = "../../configs/bf-protector_config.toml"
	config     protectorconfig.Config
	storage    *memorystorage.MemoryStorage
	app        *App
	testCtx    = context.Background()
)

func TestMain(m *testing.M) {
	var err error
	config, err = protectorconfig.NewConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}

	setup(config)
	code := m.Run()
	shutdown()

	os.Exit(code)
}

func setup(conf protectorconfig.Config) {
	storage = memorystorage.New(config)

	err := storage.Seed(context.Background(),
		[]string{constant.WhiteSubnetsKey, constant.BlackSubnetsKey},
		[][]string{getWhiteListSubnets(), getBlackListSubnets()},
	)
	if err != nil {
		err = fmt.Errorf("%s: %w", constant.DatabaseSeedErr, err)
		log.Fatal(err)
	}

	app = New(config, storage)
}

func shutdown() {
	storage.Close()
}
