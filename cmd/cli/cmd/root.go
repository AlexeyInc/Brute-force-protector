/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"log"
	"os"

	// bfprotector "github.com/AlexeyInc/Brute-force-protector/api/protoc"...
	cliconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var cfgFile string

type bfProtectorService struct {
	*grpc.ClientConn
	// client bfprotector.BruteForceProtectorServiceClient
	host string
}

var bfProtector = &bfProtectorService{}

var rootCmd = &cobra.Command{
	Use:   "cmd",
	Short: "CLI for Brute-force-protector app",
	Long: `This CLI provide manual administration of Brute-force-protector service.

What you can do:
	- authorization request
	- call a bucket reset
	- manage white/black lists`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(
		&cfgFile, "config", "../configs/cli_config.toml", "config file default path '../configs/cli_config.toml'")
}

func initConfig() {
	config, err := cliconfig.NewConfig(cfgFile)
	failOnError(err, constant.ReadConfigErr)

	bfProtector.host = config.BfProtector.Host
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
