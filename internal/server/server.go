package grpcserver

import (
	"context"
	"log"
	"net"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	"google.golang.org/grpc"
)

type Logger interface {
	Info(msg string)
}

func RunGRPCServer(context context.Context, config protectorconfig.Config, app api.BruteForceProtectorServiceServer, logger Logger) {
	gRPCServer := grpc.NewServer()

	api.RegisterBruteForceProtectorServiceServer(gRPCServer, app)

	l, err := net.Listen(config.GRPCServer.Network, config.GRPCServer.Host+config.GRPCServer.Port)
	if err != nil {
		log.Fatal("can't run listener: ", err)
	}

	go func() {
		logger.Info("calendar gRPC server is running...")

		if err = gRPCServer.Serve(l); err != nil {
			log.Fatal("can't run server: ", err)
		}
	}()

	<-context.Done()

	gRPCServer.GracefulStop()

	logger.Info("gRPC server closed.")
}
