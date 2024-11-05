/*
 *
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/DNSSEC-Provisioning/music/music"
	tdns "github.com/johanix/tdns/tdns"

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

//	rootCmd.PersistentFlags().BoolVarP(&cliconf.Verbose, "verbose", "v", false, "Verbose output")
//	rootCmd.PersistentFlags().BoolVarP(&cliconf.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&showheaders, "headers", "H", false, "Show column headers on output")
	rootCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "name of zone")
	rootCmd.PersistentFlags().StringVarP(&signername, "signer", "s", "", "name of signer")
	rootCmd.PersistentFlags().StringVarP(&sgroupname, "group", "g", "", "name of signer group")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var conf tdns.Config
	var mconf music.Config

	viper.SetConfigFile(music.DefaultSidecarTdnsCfgFile)
	if err := viper.ReadInConfig(); err == nil {
		if cliconf.Verbose {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
		err = viper.Unmarshal(&conf)
		if err != nil {
			log.Fatalf("Error unmarshalling TDNS config %s: %v", music.DefaultSidecarTdnsCfgFile, err)
		}
	} else {
		log.Fatalf("Error parsing TDNS config %s: %v", music.DefaultSidecarTdnsCfgFile, err)
	}

	// Load MUSIC config; note that this must be after the TDNS config has been parsed and use viper.MergeConfig()
	if err := music.LoadMusicConfig(&mconf, "sidecar-cli", false); err == nil {
		if cliconf.Verbose {
			fmt.Println("Using MUSIC config file:", music.DefaultSidecarCfgFile)
		}
		err = viper.Unmarshal(&mconf)
		if err != nil {
			log.Fatalf("Error unmarshalling MUSIC config: %v", err)
		}
	} else {
		log.Fatalf("Error loading MUSIC config: %v", err)
	}

	// Then read in the sidecar config. This is may be overridden by a cmdline flag.
	//	if cfgFile == "" {
	//		cfgFile = music.DefaultSidecarCfgFile
	//	}
	//	viper.SetConfigFile(cfgFile)

	//	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	//	if err := viper.MergeInConfig(); err == nil {
	//		if cliconf.Verbose {
	//			fmt.Println("Using config file:", viper.ConfigFileUsed())
	//		}
	//	}

	validate = validator.New()
	if err := validate.Struct(&mconf); err != nil {
		log.Fatalf("Config '%s' is missing required attributes:\n%v\n", music.DefaultSidecarCfgFile, err)
	}
}

func initApi() {

	baseurl := viper.GetString("cli.sidecar.baseurl")
	apikey := viper.GetString("cli.sidecar.apikey")
	authmethod := viper.GetString("cli.sidecar.authmethod")
	//rootcafile := viper.GetString("cli.sidecar.cacert")

	//	api = music.NewClient("musicd", baseurl, apikey, authmethod, rootcafile,
	//		cliconf.Verbose, cliconf.Debug)

	tdns.Globals.Api = tdns.NewClient("tdnsd", baseurl, apikey, authmethod, "insecure", tdns.Globals.Verbose, tdns.Globals.Debug)

	if tdns.Globals.Debug {
		fmt.Printf("initApi: api connection to %s initialized (%s)\n:\napi: %+v\n", baseurl, apikey, tdns.Globals.Api)
	}
}
