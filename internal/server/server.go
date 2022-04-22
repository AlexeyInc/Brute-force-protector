package grpcserver

import (
	"context"
	"fmt"
	"log"
	"net"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	"google.golang.org/grpc"
)

type Logger interface {
	Info(msg string)
	Error(msg string)
}

// TODO: remove
type Server struct {
	gRPCServer *grpc.Server
	listener   net.Listener
}

func RunGRPCServer(context context.Context, config protectorconfig.Config, app api.AuthorizationServiceServer) {
	gRPCServer := grpc.NewServer(
	//grpc.UnaryInterceptor(bruteForceProtectorMiddleware()),
	)

	api.RegisterAuthorizationServiceServer(gRPCServer, app)

	l, err := net.Listen(config.GRPCServer.Network, config.GRPCServer.Host+config.GRPCServer.Port)
	if err != nil {
		log.Fatal("can't run listener: ", err)
	}

	go func() {
		fmt.Println("calendar gRPC server is running..")

		if err = gRPCServer.Serve(l); err != nil {
			log.Fatal("can't run server: ", err)
		}
	}()

	<-context.Done()

	gRPCServer.GracefulStop()
	fmt.Println("gRPC server closed.")
}
