/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/DNSSEC-Provisioning/music/fsm"
	"github.com/DNSSEC-Provisioning/music/music"
	tdns "github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

// yes, this must be global
var tokvip *viper.Viper
var cliconf = music.CliConfig{}

// var appVersion string
var appMode string

func mainloop(conf *tdns.Config, mconf *music.Config, appMode string) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	var err error
	var all_zones []string
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// log.Println("mainloop: signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
				all_zones, err = tdns.ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true = reload
				if err != nil {
					log.Fatalf("Error parsing zones: %v", err)
				} else {
					log.Printf("mainloop: SIGHUP received. Forcing refresh of %d configured zones.", len(all_zones))
				}

			case <-conf.Internal.APIStopCh:
				log.Println("mainloop: Stop command received. Cleaning up.")
				wg.Done()
			}
		}
	}()
	wg.Wait()

	// XXX: From musicd.
	mconf.Internal.TokViper.WriteConfig()
	fmt.Printf("mainloop: saved state of API tokens to disk\n")
	fmt.Println("mainloop: leaving signal dispatcher")

	fmt.Println("mainloop: leaving signal dispatcher")
}

func LoadMusicConfig(mconf *music.Config, appMode string, safemode bool) error {
	var cfgfile string
	switch appMode {
	case "server":
		cfgfile = music.DefaultCfgFile
	case "sidecar":
		cfgfile = music.DefaultSidecarCfgFile
	default:
		log.Fatalf("Unknown app mode: %s", appMode)
	}

	fmt.Printf("LoadConfig: reloading config from \"%s\". Safemode: %v\n", cfgfile, safemode)
	if safemode {
		tmpviper := viper.New()
		tmpviper.SetConfigFile(cfgfile)

		var err error
		switch appMode {
		case "server":
			err = tmpviper.ReadInConfig()
		case "sidecar":
			err = tmpviper.MergeInConfig()
		default:
			log.Fatalf("Unknown app mode: %s", appMode)
		}
		if err != nil {
			return err
		}

		err = music.ValidateConfig(tmpviper, cfgfile, appMode, true) // will not terminate on error
		if err != nil {
			return err
		}
		fmt.Printf("LoadConfig: safe config validation succeeded, no errors. Now reloading.\n")
	}

	viper.SetConfigFile(cfgfile)

	var err error
	switch appMode {
	case "server":
		err = viper.ReadInConfig()
	case "sidecar":
		err = viper.MergeInConfig()
	default:
		log.Fatalf("Unknown app mode: %s", appMode)
	}
	if err != nil {
		log.Fatalf("Could not load config (%s)", err)
	}

	err = music.ValidateConfig(nil, cfgfile, appMode, false) // will terminate on error
	if err != nil {
		return err
	}

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
	var conf tdns.Config
	var mconf music.Config

	conf.AppMode = "sidecar"
	conf.ServerBootTime = time.Now()
	conf.AppVersion = appVersion
	conf.AppName = appName
	conf.AppDate = appDate
	// The agent is not a mode of operation, an agent should not be able to run as a server by just starting it with the wrong arguments.
	// flag.StringVar(&appMode, "mode", "agent", "Mode of operation: server | agent | scanner")

	flag.BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	flag.Parse()

	switch conf.AppMode {
	case "server", "agent", "sidecar", "scanner":
		fmt.Printf("*** TDNS mode of operation: %s (verbose: %t, debug: %t)\n", conf.AppMode, tdns.Globals.Verbose, tdns.Globals.Debug)
	default:
		log.Fatalf("*** TDNS: Error: unknown mode of operation: %s", conf.AppMode)
	}

	// XXX: From musicd.
	flag.Usage = func() {
		flag.PrintDefaults()
	}

	// These are set here to enable various config reload functions to reload from the correct files.
	conf.Internal.CfgFile = music.DefaultTdnsCfgFile
	conf.Internal.ZonesCfgFile = music.DefaultZonesCfgFile

	err := tdns.ParseConfig(&conf, false) // false = !reload, initial config
	if err != nil {
		log.Fatalf("Error parsing TDNS config %s: %v", music.DefaultTdnsCfgFile, err)
	}

	// Load MUSIC config; note that this must be after the TDNS config has been parsed and use viper.MergeConfig()
	music.LoadMusicConfig(&mconf, conf.AppMode, false) // on initial startup a config error should cause an abort.

	kdb := conf.Internal.KeyDB

	logfile := viper.GetString("log.file")
	err = tdns.SetupLogging(logfile)
	if err != nil {
		log.Fatalf("Error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)

	fmt.Printf("TDNS Multi-Signer Agent version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)

	conf.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan tdns.BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 10)
	go tdns.RefreshEngine(&conf, stopch, appMode)

	//	conf.Internal.ValidatorCh = make(chan tdns.ValidatorRequest, 10)
	// 	go ValidatorEngine(&conf, stopch)

	conf.Internal.NotifyQ = make(chan tdns.NotifyRequest, 10)
	go tdns.Notifier(conf.Internal.NotifyQ)

	// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
	_, err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, false) // false = !reload, initial config
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	apistopper := make(chan struct{}) //
	conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, &mconf, apistopper)

	conf.Internal.ScannerQ = make(chan tdns.ScanRequest, 5)
	conf.Internal.UpdateQ = kdb.UpdateQ
	conf.Internal.DnsUpdateQ = make(chan tdns.DnsUpdateRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan tdns.DnsNotifyRequest, 100)
	conf.Internal.AuthQueryQ = make(chan tdns.AuthQueryRequest, 100)

	go tdns.AuthQueryEngine(conf.Internal.AuthQueryQ)
	go tdns.ScannerEngine(conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)
	go kdb.ZoneUpdaterEngine(stopch)
	go tdns.UpdateHandler(&conf)
	go tdns.NotifyHandler(&conf)
	go tdns.DnsEngine(&conf)
	go kdb.DelegationSyncher(conf.Internal.DelegationSyncQ, conf.Internal.NotifyQ)
	// go tdns.ResignerEngine(conf.Internal.ResignQ, make(chan struct{}))

	// MUSIC stuff
	mconf.Internal = music.InternalConf{}

	mconf.Internal.EngineCheck = make(chan music.EngineCheck, 100)

	mconf.Internal.MusicDB, err = music.NewDB(viper.GetString("db.file"), viper.GetString("db.mode"), false) // Don't drop status tables if they exist
	if err != nil {
		log.Fatalf("Error from NewDB(%s): %v", viper.GetString("db.file"), err)
	}

	mconf.Internal.TokViper = tokvip
	mconf.Internal.MusicDB.Tokvip = tokvip
	fsml := fsm.NewFSMlist()
	mconf.Internal.Processes = fsml
	mconf.Internal.MusicDB.FSMlist = fsml

	// deSEC stuff
	mconf.Internal.DesecFetch = make(chan music.SignerOp, 100)
	mconf.Internal.DesecUpdate = make(chan music.SignerOp, 100)
	mconf.Internal.DdnsFetch = make(chan music.SignerOp, 100)
	mconf.Internal.DdnsUpdate = make(chan music.SignerOp, 100)

	rootcafile := viper.GetString("common.rootCA")
	desecapi, err := music.DesecSetupClient(rootcafile, cliconf.Verbose, cliconf.Debug)
	if err != nil {
		log.Fatalf("Error from DesecSetupClient: %v\n", err)
	}
	desecapi.TokViper = tokvip

	rldu := music.Updaters["rldesec-api"]
	rldu.SetChannels(mconf.Internal.DesecFetch, mconf.Internal.DesecUpdate)
	rldu.SetApi(*desecapi)
	du := music.Updaters["desec-api"]
	du.SetApi(*desecapi) // it is ok to reuse the same object here

	rlddu := music.Updaters["rlddns"]
	rlddu.SetChannels(mconf.Internal.DdnsFetch, mconf.Internal.DdnsUpdate)

	var done = make(chan struct{}, 1)

	// XXX: From musicd.
	go dbUpdater(&mconf)
	// go MusicAPIdispatcher(&mconf)
	go deSECmgr(&mconf, done)
	go ddnsmgr(&mconf, done)
	go FSMEngine(&mconf, done)

	mainloop(&conf, &mconf, appMode)
}
