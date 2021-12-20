/*
 *
 */
package cmd

import (
	"fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-playground/validator/v10"
)

var cfgFile, zonename, signername string
var showheaders bool

var tokvip *viper.Viper
var cliconf = music.CliConfig{}
var api *music.Api

var validate *validator.Validate

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "music-cli",
	Short: "Client for musicd",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initApi)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", DefaultCfgFile))

	rootCmd.PersistentFlags().BoolVarP(&cliconf.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&cliconf.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&showheaders, "headers", "H", false, "Show column headers on output")
	rootCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "name of zone")
	rootCmd.PersistentFlags().StringVarP(&signername, "name", "s", "", "name of signer")
	rootCmd.PersistentFlags().StringVarP(&sgroupname, "group", "g",	"", "name of signer group")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(DefaultCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if cliconf.Verbose {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("unable to unmarshal the config %v", err)
	}

	validate = validator.New()
	if err := validate.Struct(&config); err != nil {
		log.Fatalf("Missing required attributes %v\n", err)
	}

	tokvip = viper.New()
	tokenfile := DefaultTokenFile
	if viper.GetString("login.tokenfile") != "" {
		tokenfile = viper.GetString("login.tokenfile")
	}

	tokvip.SetConfigFile(tokenfile)
	if err := tokvip.ReadInConfig(); err == nil {
		if cliconf.Verbose {
			fmt.Println("Using token store file:", tokvip.ConfigFileUsed())
		}
	}
}

func initApi() {

	baseurl := viper.GetString("musicd.baseurl")
	apikey 	:= viper.GetString("musicd.apikey")
	authmethod := viper.GetString("musicd.authmethod")
	rootcafile := viper.GetString("musicd.rootCApem")

	api = music.NewClient("musicd", baseurl, apikey, authmethod, rootcafile,
	      			        cliconf.Verbose, cliconf.Debug)
}
