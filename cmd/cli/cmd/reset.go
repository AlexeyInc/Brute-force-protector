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

func resetCmd() *cobra.Command {
	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Resets bucket(s)",
		Long:  `...`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("reset called")

			if len(args) < 2 {
				fmt.Println("please provide in args 'login' and 'ip'")
			}

			conn, err := grpc.Dial(bfProtector.host, grpc.WithTransportCredentials(insecure.NewCredentials()))
			failOnError(err, constant.CreateClientErr)
			defer conn.Close()

			client := bfprotector.NewBruteForceProtectorServiceClient(conn)

			resp, err := client.ResetBuckets(cmd.Context(), &bfprotector.ResetBucketRequest{
				Login: args[0],
				Ip:    args[1],
			})
			failOnError(err, constant.BfProtectorReqErr)

			fmt.Println("Success: ", resp.Success)
			fmt.Println("Msg: ", resp.Msg)
		},
	}
	return resetCmd
}

func init() {
	rootCmd.AddCommand(resetCmd())
}
