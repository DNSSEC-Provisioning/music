//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package main

import (
	// "database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"

	// "github.com/jinzhu/gorm"
	// _ "github.com/jinzhu/gorm/dialects/sqlite"

	"github.com/DNSSEC-Provisioning/music/common"
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
	if err := tokvip.ReadInConfig(); err == nil {
		if cliconf.Verbose {
			fmt.Println("Using token store file:", tokvip.ConfigFileUsed())
		}
	}

	cliconf.Verbose = viper.GetBool("common.verbose")
	cliconf.Debug = viper.GetBool("common.debug")

	return nil
}

// func initialMigration() {
//     db, err := gorm.Open("sqlite3", viper.GetString("common.gormdb"))
//     if err != nil {
//         fmt.Println(err.Error())
//         panic("failed to connect to gorm database")
//     }
//     defer db.Close()
//
//     // Migrate the schema
//     // db.AutoMigrate(&music.Zone{})
//     db.AutoMigrate(&music.Signer{})
//     db.AutoMigrate(&music.GormSignerGroup{})
//     // Gorm barfs on FSMState, because that contains a func() which is unsupported in sqlite
//     // db.AutoMigrate(&music.FSMState{})
//     // Gorm barfs on FSMState, because that contains a map[] which is unsupported in sqlite
//     // db.AutoMigrate(&music.FSM{})
// }

func main() {
	var conf Config
	flag.Usage = func() {
		flag.PrintDefaults()
	}

	LoadConfig(&conf, false) // on initial startup a config error should cause an abort.

	// initialise empty conf.Internal struct
	conf.Internal = InternalConf{}

	apistopper := make(chan struct{})

	conf.Internal.MusicDB = music.NewDB(false) // Don't drop status tables if they exist
	conf.Internal.TokViper = tokvip
	conf.Internal.MusicDB.Tokvip = tokvip

	conf.Internal.DesecFetch = make(chan DesecOp, 100)
	conf.Internal.DesecUpdate = make(chan DesecOp, 100)
	var done = make(chan struct{}, 1)

	// initialMigration()
	go APIdispatcher(&conf)
	go deSECmgr(&conf, done)
	mainloop(&conf, apistopper)
}
