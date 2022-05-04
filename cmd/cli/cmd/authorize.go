/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	bfprotector "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var authorizeCmd = &cobra.Command{
	Use:   "authorize",
	Short: "authorization check",
	Long:  `example: bg-cli authorize (your login) (your password) (your ip)`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("authorize request...")

		if len(args) < 3 {
			fmt.Println("please provide in args: 'login', 'password' and 'ip'")
			return
		}

		conn, err := grpc.Dial(bfProtector.host, grpc.WithTransportCredentials(insecure.NewCredentials()))
		failOnError(err, constant.CreateClientErr)
		defer conn.Close()

		cliClient := bfprotector.NewBruteForceProtectorServiceClient(conn)

		resp, err := cliClient.Authorization(cmd.Context(), &bfprotector.AuthRequest{
			Login:    args[0],
			Password: args[1],
			Ip:       args[2],
		})
		failOnError(err, constant.BfProtectorReqErr)

		fmt.Println("Success:", resp.Success)
		fmt.Println("Msg:", resp.Msg)
	},
}

func init() {
	rootCmd.AddCommand(authorizeCmd)
}
