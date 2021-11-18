/*
 * apiserver.go
 *
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	// "github.com/miekg/dns"

	music "github.com/DNSSEC-Provisioning/music/common"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

func homeLink(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome home!")
}

func API_NYI(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "NYI")

		status := 101
		resp := "NYI"

		apistatus := music.APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apistatus)
	}
}

func APIGoAway(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		status := 404
		resp := "These are not the droids you're looking for"

		apistatus := music.APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apistatus)
	}
}

var pongs int = 0

func APIping(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIping: received /ping request from %s.\n", r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp music.PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIping: error decoding ping post:", err)
		}
		pongs += 1
		response := music.PingResponse{
			Time:    time.Now(),
			Client:  r.RemoteAddr,
			Message: "pong",
			Pings:   pp.Pings + 1,
			Pongs:   pongs}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func APIzone(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zp music.ZonePost
		err := decoder.Decode(&zp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APIzone: received /zone request (command: %s) from %s.\n",
			zp.Command, r.RemoteAddr)

		var resp = music.ZoneResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		dbzone, _ := mdb.GetZone(zp.Zone.Name) // Get a more complete Zone structure
		w.Header().Set("Content-Type", "application/json")

		switch zp.Command {
		case "list":

		case "add":
			err, resp.Msg = mdb.AddZone(dbzone, zp.SignerGroup)
			if err != nil {
				// log.Printf("Error from AddZone: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "delete":
			err, resp.Msg = mdb.DeleteZone(dbzone)
			if err != nil {
				// log.Printf("Error from DeleteZone: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "join":
			err, resp.Msg = mdb.ZoneJoinGroup(dbzone, zp.SignerGroup)
			if err != nil {
				// log.Printf("Error from ZoneJoinGroup: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "leave":
			err, resp.Msg = mdb.ZoneLeaveGroup(dbzone, zp.SignerGroup)
			if err != nil {
				// log.Printf("Error from ZoneLeaveGroup: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "fsm":
			err, resp.Msg = mdb.ZoneAttachFsm(dbzone, zp.FSM)
			if err != nil {
				// log.Printf("Error from ZoneAttachFsm: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "step-fsm":
			// var zones map[string]music.Zone
			// var success bool
			// err, resp.Msg, zones = mdb.ZoneStepFsm(dbzone, zp.FsmNextState)
			_, err, resp.Msg = mdb.ZoneStepFsm(dbzone, zp.FsmNextState)
			if err != nil {
				// log.Printf("Error from ZoneStepFsm: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
				// resp.Zones = zones
				// resp.Zones = map[string]Zone{ dbzone.Name: *dbzone }
				// w.Header().Set("Content-Type", "application/json")
			}
			dbzone, _ = mdb.GetZone(dbzone.Name)
			resp.Zones = map[string]music.Zone{dbzone.Name: *dbzone}
			json.NewEncoder(w).Encode(resp)
			return

		case "get-rrsets":
			// var rrsets map[string][]dns.RR
			err, msg, _ := mdb.ZoneGetRRsets(dbzone, zp.Owner, zp.RRtype)
			resp.Msg = msg
			if err != nil {
				// log.Printf("Error from ZoneGetRRset: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// dbzone, _ := mdb.GetZone(zp.Zone.Name)
				sg := dbzone.SignerGroup()
				// fmt.Printf("APIzone: get-rrsets: zone: %v sg: %v\n", zp.Zone, sg)

				var result = map[string][]string{}
				var rrset []string
				for k, _ := range sg.Signers() {
					err, resp.Msg, rrset = mdb.ListRRset(dbzone, k, zp.Owner,
						zp.RRtype)
					if err != nil {
						log.Fatalf("APIzone: get-rrsets: Error from ListRRset: %v\n", err)
					} else {
						result[k] = rrset
					}
				}
				resp.RRsets = result
				// fmt.Printf("get:rrsets: len: %d\n", len(rrsets))
			}
			json.NewEncoder(w).Encode(resp)
			return

		case "copy-rrset":
			fmt.Printf("APIzone: copy-rrset: %s %s %s\n", dbzone.Name,
				zp.Owner, zp.RRtype)
			// var rrset []dns.RR
			err, resp.Msg = mdb.ZoneCopyRRset(dbzone, zp.Owner, zp.RRtype,
				zp.FromSigner, zp.ToSigner)
			if err != nil {
				log.Printf("Error from ZoneCopyRRset: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// resp.RRset = rrset
				// fmt.Printf("copy:rrset: len: %d\n", len(rrset))
			}
			// w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return

		case "list-rrset":
			var rrset []string
			err, resp.Msg, rrset = mdb.ListRRset(dbzone, zp.Signer,
				zp.Owner, zp.RRtype)
			if err != nil {
				log.Printf("Error from ListRRset: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.RRset = rrset
			}
			// w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return

		case "meta":
			err, resp.Msg = mdb.ZoneMeta(dbzone, zp.Metakey, zp.Metavalue)
			if err != nil {
				// log.Printf("Error from ZoneMeta: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		default:
		}

		zs, err := mdb.ListZones()
		if err != nil {
			log.Printf("Error from ListZones: %v", err)
		}
		resp.Zones = zs

		// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)

		// w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIsigner(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var sp music.SignerPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIsigner: error decoding signer post:",
				err)
		}

		log.Printf("APIsigner: received /signer request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		var resp = music.SignerResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		dbsigner, _ := mdb.GetSigner(&sp.Signer)

		//        if sp.Command != "list" {
		//            dbsigner, err = mdb.GetSigner(sp.Signer.Name)
		//        }

		switch sp.Command {
		case "list":
			ss, err := mdb.ListSigners()
			if err != nil {
				log.Printf("Error from GetSigners: %v", err)
			}
			resp.Signers = ss

		case "add":
			err, resp.Msg = mdb.AddSigner(dbsigner)
			if err != nil {
				// log.Printf("Error from AddSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "update":
			err, resp.Msg = mdb.UpdateSigner(dbsigner)
			if err != nil {
				// log.Printf("Error from UpdateSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "delete":
			err, resp.Msg = mdb.DeleteSigner(dbsigner)
			if err != nil {
				// log.Printf("Error from DeleteSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "join":
			err, resp.Msg = mdb.SignerJoinGroup(dbsigner, sp.Signer.SignerGroup)
			if err != nil {
				// log.Printf("Error from SignerJoinGroup: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "leave":
			err, resp.Msg = mdb.SignerLeaveGroup(dbsigner, sp.Signer.SignerGroup)
			if err != nil {
				// log.Printf("Error from SignerLeaveGroup: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "login":
			err, resp.Msg = mdb.SignerLogin(dbsigner, &cliconf, tokvip)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "logout":
			err, resp.Msg = mdb.SignerLogout(dbsigner, &cliconf, tokvip)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		default:
		}

		ss, err := mdb.ListSigners()
		if err != nil {
			log.Printf("Error from GetSigners: %v", err)
		}
		resp.Signers = ss

		// fmt.Printf("APIsigner: resp struct: %v\n", resp)
		// fmt.Printf("APIsigner: resp struct error field: %v\n", resp.Error)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIsignergroup(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIsignergroup: received /signergroup request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var sgp music.SignerGroupPost
		err := decoder.Decode(&sgp)
		if err != nil {
			log.Println("APIsignergroup: error decoding signergroup post:",
				err)
		}

		var resp = music.SignerGroupResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		fmt.Printf("apiserver: /signergroup %v\n", sgp)

		switch sgp.Command {
		case "list":

		case "add":
			fmt.Printf("apiserver: AddSignerGroup\n")
			err := mdb.AddSignerGroup(sgp.Name)
			if err != nil {
				log.Printf("Error from AddSignerGroup: %v", err)
			}

		case "delete":
			err := mdb.DeleteSignerGroup(sgp.Name)
			if err != nil {
				log.Printf("Error from DeleteSignerGroup: %v", err)
			}
		default:

		}

		ss, err := mdb.ListSignerGroups()
		if err != nil {
			log.Printf("Error from ListSignerGroups: %v", err)
		}
		resp.SignerGroups = ss

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIprocess(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIprocess: received /process request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp music.ProcessPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIprocess: error decoding process post:", err)
		}

		var resp = music.ProcessResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		fmt.Printf("apiserver: /process %v\n", pp)

		switch pp.Command {
		case "list":
			sp, err, msg := mdb.ListProcesses()
			if err != nil {
				log.Printf("Error from ListProcesses: %v", err)
				resp.Error = true
				resp.ErrorMsg = msg
			}
			resp.Processes = sp

		case "graph":
			graph, err := mdb.GraphProcess(pp.Process)
			if err != nil {
				log.Printf("Error from GraphProcess: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Graph = graph

		default:

		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIshowAPI(conf *Config, router *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	address := viper.GetString("services.apiserver.api")
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIshowAPI: received /show/api request from %s.\n", r.RemoteAddr)
		message := "All ok, here's the stuff"

		resp := []string{fmt.Sprintf("API provided by STATUSD listening on: %s",
			address)}

		walker := func(route *mux.Route, router *mux.Router,
			ancestors []*mux.Route) error {
			path, _ := route.GetPathTemplate()
			methods, _ := route.GetMethods()
			for m := range methods {
				// resp += fmt.Sprintf("%-6s %s\n", methods[m], path)
				resp = append(resp, fmt.Sprintf("%-6s %s",
					methods[m], path))
			}
			return nil
		}
		if err := router.Walk(walker); err != nil {
			log.Panicf("Logging err: %s\n", err.Error())
		}
		response := music.ShowAPIresponse{
			Status:  101,
			Message: message,
			Data:    resp,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func SetupRouter(conf *Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", homeLink)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key",
		viper.GetString("apiserver.apikey")).Subrouter()
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/signer", APIsigner(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(conf)).Methods("POST")
	sr.HandleFunc("/signergroup", APIsignergroup(conf)).Methods("POST")
	sr.HandleFunc("/process", APIprocess(conf)).Methods("POST")
	sr.HandleFunc("/show/api", APIshowAPI(conf, r)).Methods("POST", "GET")

	return r
}

func walkRoutes(router *mux.Router, address string) {
	log.Printf("Defined API endpoints for router on: %s\n", address)

	walker := func(route *mux.Route, router *mux.Router,
		ancestors []*mux.Route) error {
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
	//    return nil
}

// In practice APIdispatcher doesn't need a termination signal, as it will
// just sit inside http.ListenAndServe, but we keep it  for  symmetry.
//
// func APIdispatcher(conf *Config, done <-chan struct{}) {
func APIdispatcher(conf *Config) error {
	router := SetupRouter(conf)
	address := viper.GetString("apiserver.address")
	certFile := viper.GetString("apiserver.certFile")
	keyFile := viper.GetString("apiserver.keyFile")

	if address != "" {
		log.Println("Starting API dispatcher. Listening on", address)
		log.Fatal(http.ListenAndServeTLS(address, certFile, keyFile, router))
	}

	log.Println("API dispatcher: unclear how to stop the http server nicely.")
	return nil
}
