//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"github.com/DNSSEC-Provisioning/music/common"
	"github.com/DNSSEC-Provisioning/music/fsm"
)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] cmd ...\n", os.Args[0])
	flag.PrintDefaults()
}

// yes, this must be global
var tokvip *viper.Viper
var cliconf = music.CliConfig{}

//
// This will wait forever on an external signal, but even better would be
// if we could wait on an external signal OR an internal quit channel. TBD.
//
func mainloop(conf *Config, apistopper chan struct{}) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	fmt.Println("mainloop: entering signal dispatcher")

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// fmt.Println("mainloop: inside signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				//    var done struct{}
				//    clistopper <- done
				log.Println("mainloop: SIGTERM/SIGINT received, stopping.")

				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-apistopper:
				log.Println("mainloop: API stop received. Cleaning up.")

				// wait a little bit to allow current api
				// call to return
				time.Sleep(1 * time.Second)
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				log.Println("mainloop: SIGHUP received.")
			}
		}
	}()
	wg.Wait()

	conf.Internal.TokViper.WriteConfig()
	fmt.Printf("mainloop: saved state of API tokens to disk\n")
	fmt.Println("mainloop: leaving signal dispatcher")
}

func LoadConfig(conf *Config, safemode bool) error {
	fmt.Printf("LoadConfig: reloading config from \"%s\". Safemode: %v\n",
		DefaultCfgFile, safemode)
	if safemode {
		tmpviper := viper.New()
		tmpviper.SetConfigFile(DefaultCfgFile)

		err := tmpviper.ReadInConfig()
		if err != nil {
			return err
		}

		err = ValidateConfig(tmpviper, DefaultCfgFile, true) // will not terminate on error
		if err != nil {
			return err
		}
		fmt.Printf("LoadConfig: safe config validation succeeded, no errors. Now reloading.\n")
	}

	viper.SetConfigFile(DefaultCfgFile)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Could not load config (%s)", err)
	}

	ValidateConfig(nil, DefaultCfgFile, false) // will terminate on error

	tokvip = viper.New()
	var tokenfile string
	if viper.GetString("common.tokenfile") != "" {
		tokenfile = viper.GetString("common.tokenfile")
	}

	tokvip.SetConfigFile(tokenfile)
	err = tokvip.ReadInConfig()
	if err != nil {
	       log.Printf("Error from tokvip.ReadInConfig: %v\n", err)
	} else {
		if cliconf.Verbose {
			fmt.Println("Using token store file:", tokvip.ConfigFileUsed())
		}
	}

	cliconf.Verbose = viper.GetBool("common.verbose")
	cliconf.Debug = viper.GetBool("common.debug")

	return nil
}

func main() {
	var conf Config
	var err error

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	LoadConfig(&conf, false) // on initial startup a config error should cause an abort.

	// initialise empty conf.Internal struct
	conf.Internal = InternalConf{}

	apistopper := make(chan struct{})
	conf.Internal.EngineCheck = make(chan music.EngineCheck, 100)

	conf.Internal.MusicDB, err = music.NewDB(viper.GetString("db.file"), viper.GetString("db.mode"), false) // Don't drop status tables if they exist
	if err != nil {
	   log.Fatalf("Error from NewDB(%s): %v", viper.GetString("db.file"), err)
	}
	
	conf.Internal.TokViper = tokvip
	conf.Internal.MusicDB.Tokvip = tokvip
	fsml := fsm.NewFSMlist()
	conf.Internal.Processes = fsml
	conf.Internal.MusicDB.FSMlist = fsml

	// deSEC stuff
	conf.Internal.DesecFetch = make(chan music.SignerOp, 100)
	conf.Internal.DesecUpdate = make(chan music.SignerOp, 100)
	conf.Internal.DdnsFetch = make(chan music.SignerOp, 100)
	conf.Internal.DdnsUpdate = make(chan music.SignerOp, 100)

	rootcafile := viper.GetString("common.rootCA")
	desecapi, err := music.DesecSetupClient(rootcafile, cliconf.Verbose, cliconf.Debug)
	if err != nil {
	   log.Fatalf("Error from DesecSetupClient: %v\n", err)
	}
	desecapi.TokViper = tokvip

	rldu := music.Updaters["rldesec-api"]
	rldu.SetChannels(conf.Internal.DesecFetch, conf.Internal.DesecUpdate)
	rldu.SetApi(*desecapi)
	du := music.Updaters["desec-api"]
	du.SetApi(*desecapi)			// it is ok to reuse the same object here

	rlddu := music.Updaters["rlddns"]
	rlddu.SetChannels(conf.Internal.DdnsFetch, conf.Internal.DdnsUpdate)

	var done = make(chan struct{}, 1)

	go dbUpdater(&conf)
	go APIdispatcher(&conf)
	go deSECmgr(&conf, done)
	go ddnsmgr(&conf, done)
	go FSMEngine(&conf, done)

	mainloop(&conf, apistopper)
}
