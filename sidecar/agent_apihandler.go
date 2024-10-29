/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/DNSSEC-Provisioning/music/music"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/tdns"
)

func APIcommand(conf *tdns.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp tdns.CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := tdns.CommandResponse{
			Time: time.Now(),
		}

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp.Status = "ok" // only status we know, so far
			resp.Msg = "We're happy, but send more cookies"

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			// var done struct{}
			resp.Status = "stopping"
			resp.Msg = "Daemon was happy, but now winding down"

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json.Encode(): %v", err)
			}
			time.Sleep(500 * time.Millisecond)
			conf.Internal.APIStopCh <- struct{}{}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from json.Encode(): %v", err)
		}
	}
}

func SetupRouter(tconf *tdns.Config, mconf *music.Config) *mux.Router {
	kdb := tconf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()

	// TDNS stuff
	sr.HandleFunc("/ping", tdns.APIping(tconf, tconf.AppName, tconf.AppVersion, tconf.ServerBootTime)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone", tdns.APIzone(tconf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(tconf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", tdns.APIdebug()).Methods("POST")

	// The /command endpoint is the only one not in the tdns lib
	sr.HandleFunc("/command", APIcommand(tconf)).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	// MUSIC stuff
	// sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/signer", music.APIsigner(mconf)).Methods("POST")
	sr.HandleFunc("/zone", music.APIzone(mconf)).Methods("POST")
	sr.HandleFunc("/signergroup", music.APIsignergroup(mconf)).Methods("POST")
	sr.HandleFunc("/test", music.APItest(mconf)).Methods("POST")
	sr.HandleFunc("/process", music.APIprocess(mconf)).Methods("POST")
	sr.HandleFunc("/show", music.APIshow(mconf, r)).Methods("POST")

	return r
}

func walkRoutes(router *mux.Router, address string) {
	log.Printf("Defined API endpoints for router on: %s\n", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			log.Printf("%-6s %s\n", methods[m], path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		log.Panicf("Logging err: %s\n", err.Error())
	}
	//	return nil
}

// This is the sidecar mgmt API dispatcher.
func APIdispatcher(tconf *tdns.Config, mconf *music.Config, done <-chan struct{}) {
	router := SetupRouter(tconf, mconf)

	walkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	address := viper.GetString("apiserver.address")

	go func() {
		if address != "" {
			log.Println("Starting API dispatcher #1. Listening on", address)
			log.Fatal(http.ListenAndServeTLS(address, viper.GetString("apiserver.certFile"),
				viper.GetString("apiserver.keyFile"), router))
		} else {
			log.Println("API dispatcher #1: address not set, not starting")
		}
	}()

	log.Println("API dispatcher: unclear how to stop the http server nicely.")
}
