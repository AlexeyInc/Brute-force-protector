package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var pathToLogFile string

type Logger struct {
	ZapLogger *zap.Logger
}

func New(logFile string) *Logger {
	pathToLogFile = logFile
	writeSyncer := getLogWriter()
	encoder := getEncoder()
	core := zapcore.NewCore(encoder, writeSyncer, zapcore.InfoLevel)

	logger := zap.New(core)

	return &Logger{
		ZapLogger: logger,
	}
}

func (l Logger) Info(msg string) {
	l.ZapLogger.Info(msg)
}

func (l Logger) Error(msg string) {
	l.ZapLogger.Error(msg)
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getLogWriter() zapcore.WriteSyncer {
	file, err := os.OpenFile(pathToLogFile, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		panic("can't create logger: " + err.Error())
	}
	return zapcore.AddSync(file)
}
