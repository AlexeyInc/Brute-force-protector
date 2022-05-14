/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	bfprotector "github.com/AlexeyInc/Brute-force-protector/pkg/grpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func reserveCmd() *cobra.Command {
	var actionType string
	var listType string

	reserveCmd := &cobra.Command{
		Use:   "reserve",
		Short: "managing of white/black lists",
		Long:  `example: bfp-cli --action=add --list=white (your test IPNet)`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("reserve reqeust...")

			if len(args) < 1 {
				fmt.Println("please provide in args 'ip'")
				return
			}

			conn, err := grpc.Dial(bfProtector.host, grpc.WithTransportCredentials(insecure.NewCredentials()))
			failOnError(err, constant.CreateClientErr)
			defer conn.Close()

			cliClient := bfprotector.NewBruteForceProtectorServiceClient(conn)

			ctx := cmd.Context()
			ip := &bfprotector.SubnetRequest{
				Cidr: args[0],
			}

			resp := &bfprotector.StatusResponse{}
			switch actionType {
			case "add":
				switch listType {
				case "white":
					resp, err = cliClient.AddWhiteListIP(ctx, ip)
					failOnError(err, constant.WhiteListAddErr)
				case "black":
					resp, err = cliClient.AddBlackListIP(ctx, ip)
					failOnError(err, constant.BlackListAddErr)
				}
			case "remove":
				switch listType {
				case "white":
					resp, err = cliClient.DeleteWhiteListIP(ctx, ip)
					failOnError(err, constant.WhiteListRemoveErr)
				case "black":
					resp, err = cliClient.DeleteBlackListIP(ctx, ip)
					failOnError(err, constant.BlackListRemoveErr)
				}
			}

			fmt.Println("Success:", resp.Success)
			fmt.Println("Msg:", resp.Msg)
		},
	}

	reserveCmd.Flags().StringVarP(&actionType, "action", "a", "add", "type of action (add/remove)")
	reserveCmd.Flags().StringVarP(&listType, "list", "l", "white", "type of list (white/black)")
	return reserveCmd
}

func init() {
	rootCmd.AddCommand(reserveCmd())
}
