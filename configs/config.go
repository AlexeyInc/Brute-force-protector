package protectorconfig

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Storage       StorageConf
	GRPCServer    ServerConf
	AttemptsLimit AttemptLimitConf
	BfProtector   BfProtectorConf
}

type StorageConf struct {
	Source   string
	Password string
}

type ServerConf struct {
	Host    string
	Port    string
	Network string
}

type AttemptLimitConf struct {
	LoginRequestsMinute    int
	PasswordRequestsMinute int
	IPRequestsMinute       int
}

type BfProtectorConf struct {
	Host string
}

func NewConfig(fullPath string) (config Config, err error) {
	pathToFile, fileName, fileType := getFileInfo(fullPath)
	viper.AddConfigPath(pathToFile)
	viper.SetConfigName(fileName)
	viper.SetConfigType(fileType)

	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}

func getFileInfo(filePath string) (path, fileName, fileType string) {
	pathChanks := strings.Split(filePath, "/")

	sb := strings.Builder{}
	for i := 0; i < len(pathChanks)-1; i++ {
		sb.WriteString(pathChanks[i])
		sb.WriteString("/")
	}
	path = sb.String()
	fileName = strings.Split(pathChanks[len(pathChanks)-1], ".")[0]
	fileType = strings.Split(pathChanks[len(pathChanks)-1], ".")[1]
	return
}
