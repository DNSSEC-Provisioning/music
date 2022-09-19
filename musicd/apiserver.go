/*
 * apiserver.go
 *
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DNSSEC-Provisioning/music/common"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
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

		apistatus := common.APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(apistatus)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIGoAway(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		status := 404
		resp := "These are not the droids you're looking for"

		apistatus := common.APIstatus{Status: status, Message: resp}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(apistatus)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

var pongs int = 0

func APIping(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIping: received /ping request from %s.\n", r.RemoteAddr)

		tls := ""
		if r.TLS != nil {
			tls = "TLS "
		}

		decoder := json.NewDecoder(r.Body)
		var pp common.PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIping: error decoding ping post:", err)
		}

		pongs += 1

		for i := 1; i < pp.Fetches; i++ {
			conf.Internal.DesecFetch <- common.SignerOp{}
		}
		for i := 1; i < pp.Updates; i++ {
			conf.Internal.DesecUpdate <- common.SignerOp{}
		}

		host, _ := os.Hostname()
		response := common.PingResponse{
			Time:    time.Now(),
			Client:  r.RemoteAddr,
			Message: fmt.Sprintf("%spong from musicd @ %s", tls, host),
			Pings:   pp.Pings + 1,
			Pongs:   pongs}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APItest(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var tp common.TestPost
		err := decoder.Decode(&tp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APItest: received /test request (command: %s) from %s.\n",
			tp.Command, r.RemoteAddr)

		var resp = common.TestResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		w.Header().Set("Content-Type", "application/json")

		switch tp.Command {
		case "dnsquery":
			signer, err := mdb.GetSigner(nil, &common.Signer{Name: tp.Signer}, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			updater := common.GetUpdater(signer.Method)
			if updater == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error: Unknown updater: '%s'.", tp.Updater)

			}
			rrtype := dns.StringToType[tp.RRtype]
			if !resp.Error {
				i := 0
				queuedepth := 0
				switch signer.Method {
				case "ddns", "desec-api":
					queuedepth = 0
				case "rlddns":
					queuedepth = len(conf.Internal.DdnsFetch)
				case "rldesec":
					queuedepth = len(conf.Internal.DesecFetch)
				}

				fmt.Printf("Test DNS Query: currently %d fetch requests in the '%s' fetch queue.\n",
					queuedepth, signer.Method)
				fmt.Printf("Test DNS Query: will send %d queries for '%s %s'\n",
					tp.Count, tp.Qname, tp.RRtype)
				for i = 0; i < tp.Count; i++ {
					// err, _ = updater.FetchRRset(signer, tp.Zone, tp.Qname, rrtype)
					go updater.FetchRRset(signer, tp.Zone, tp.Qname, rrtype)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
						break
					}
					fmt.Printf("Test DNS Query: query %d (of %d) done.\n", i, tp.Count)
				}
				resp.Message = fmt.Sprintf("All %d fetch requests done\n", i)
			}

		default:
		}

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIzone(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	enginecheck := conf.Internal.EngineCheck // need to be able to send this to Zone{Add,...}

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zp common.ZonePost
		err := decoder.Decode(&zp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APIzone: received /zone request (command: %s) from %s.\n",
			zp.Command, r.RemoteAddr)

		var resp = common.ZoneResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}
		w.Header().Set("Content-Type", "application/json")

		dbzone, _, err := mdb.GetZone(nil, zp.Zone.Name) // Get a more complete Zone structure
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			switch zp.Command {
			case "list":
				zs, err := mdb.ListZones()
				if err != nil {
					log.Printf("Error from ListZones: %v", err)
				}
				resp.Zones = zs
			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
			case "status":
				var zl = make(map[string]common.Zone, 1)
				if dbzone.Exists {
					sg, err := mdb.GetSignerGroup(nil, dbzone.SGname, true)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {

						zl[dbzone.Name] = common.Zone{
							Name:       dbzone.Name,
							State:      dbzone.State,
							Statestamp: dbzone.Statestamp,
							NextState:  dbzone.NextState,
							FSM:        dbzone.FSM,
							SGroup:     sg,
							SGname:     sg.Name,
						}
						resp.Zones = zl
					}

				} else {
					message := fmt.Sprintf("Zone %s: not in DB", zp.Zone.Name)
					log.Println(message)
					resp.Msg = message
				}

			case "add":
				fmt.Printf("apiserver:/zone: zone: %v group: '%s'", zp.Zone, zp.SignerGroup)
				resp.Msg, err = mdb.AddZone(&zp.Zone, zp.SignerGroup, enginecheck)
				if err != nil {
					// log.Printf("Error from AddZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "update":
				// err, resp.Msg = mdb.AddZone(dbzone, zp.SignerGroup, enginecheck)
				resp.Msg, err = mdb.UpdateZone(dbzone, &zp.Zone, enginecheck)
				if err != nil {
					// log.Printf("Error from UpdateZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "delete":
				resp.Msg, err = mdb.DeleteZone(dbzone)
				if err != nil {
					// log.Printf("Error from DeleteZone: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "join":
				resp.Msg, err = mdb.ZoneJoinGroup(nil, dbzone, zp.SignerGroup, enginecheck)
				if err != nil {
					// log.Printf("Error from ZoneJoinGroup: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "leave":
				resp.Msg, err = mdb.ZoneLeaveGroup(nil, dbzone, zp.SignerGroup)
				if err != nil {
					// log.Printf("Error from ZoneLeaveGroup: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			// XXX: A single zone cannot "choose" to join an FSM, it's the Group that does that.
			//      This endpoint is only here for development and debugging reasons.
			case "fsm":
				resp.Msg, err = mdb.ZoneAttachFsm(nil, dbzone, zp.FSM, zp.FSMSigner, false)
				if err != nil {
					// log.Printf("Error from ZoneAttachFsm: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			case "step-fsm":
				// var zones map[string]common.Zone
				// var success bool
				// err, resp.Msg, zones = mdb.ZoneStepFsm(nil, dbzone, zp.FsmNextState)
				// log.Printf("APISERVER: STEP-FSM: Calling ZoneStepFsm for zone %s and %v\n", dbzone.Name, zp.FsmNextState)
				var success bool
				success, resp.Msg, err = mdb.ZoneStepFsm(nil, dbzone, zp.FsmNextState)
				if err != nil {
					log.Printf("APISERVER: Error from ZoneStepFsm: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
					// resp.Zones = zones
					// resp.Zones = map[string]Zone{ dbzone.Name: *dbzone }
					// w.Header().Set("Content-Type", "application/json")
				}
				log.Printf("APISERVER: STEP-FSM: pre GetZone\n")
				dbzone, _, err = mdb.ApiGetZone(dbzone.Name) // apisafe
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if !success {
						dbzone.StopReason, err = mdb.ZoneGetMeta(nil, dbzone, "stop-reason")
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						}
					}
					resp.Zones = map[string]common.Zone{dbzone.Name: *dbzone}
				}
				err = json.NewEncoder(w).Encode(resp)
				if err != nil {
					log.Printf("Error from Encoder: %v\n", err)
				}
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
					// dbzone, _ := mdb.GetZone(nil, zp.Zone.Name)
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
				err = json.NewEncoder(w).Encode(resp)
				if err != nil {
					log.Printf("Error from Encoder: %v\n", err)
				}
				return

			case "copy-rrset":
				fmt.Printf("APIzone: copy-rrset: %s %s %s\n", dbzone.Name,
					zp.Owner, zp.RRtype)
				// var rrset []dns.RR
				err, resp.Msg = mdb.ZoneCopyRRset(nil, dbzone, zp.Owner, zp.RRtype,
					zp.FromSigner, zp.ToSigner)
				if err != nil {
					log.Printf("Error from ZoneCopyRRset: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// resp.RRset = rrset
					// fmt.Printf("copy:rrset: len: %d\n", len(rrset))
				}
				err = json.NewEncoder(w).Encode(resp)
				if err != nil {
					log.Printf("Error from Encoder: %v\n", err)
				}
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
				err = json.NewEncoder(w).Encode(resp)
				if err != nil {
					log.Printf("Error from Encoder: %v\n", err)
				}
				return

			case "meta":
				dbzone.ZoneType = zp.Zone.ZoneType
				resp.Msg, err = mdb.ZoneSetMeta(nil, dbzone, zp.Metakey, zp.Metavalue)
				if err != nil {
					// log.Printf("Error from ZoneSetMeta: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

			default:
			}
		}
		/*
			zs, err := mdb.ListZones()
			if err != nil {
				log.Printf("Error from ListZones: %v", err)
			}
			resp.Zones = zs
			// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
		*/
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIsigner(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var sp common.SignerPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIsigner: error decoding signer post:",
				err)
		}

		log.Printf("APIsigner: received /signer request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		var resp = common.SignerResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		dbsigner, _ := mdb.GetSigner(nil, &sp.Signer, false) // not apisafe

		switch sp.Command {
		case "list":
			ss, err := mdb.ListSigners(nil)
			if err != nil {
				log.Printf("Error from GetSigners: %v", err)
			}
			resp.Signers = ss

		case "add":
			resp.Msg, err = mdb.AddSigner(nil, dbsigner, sp.SignerGroup)
			if err != nil {
				// log.Printf("Error from AddSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "update":
			resp.Msg, err = mdb.UpdateSigner(nil, dbsigner, sp.Signer)
			if err != nil {
				// log.Printf("Error from UpdateSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "delete":
			resp.Msg, err = mdb.DeleteSigner(nil, dbsigner)
			if err != nil {
				// log.Printf("Error from DeleteSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "join":
			resp.Msg, err = mdb.SignerJoinGroup(nil, dbsigner, sp.Signer.SignerGroup)
			if err != nil {
				// log.Printf("Error from SignerJoinGroup: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "leave":
			resp.Msg, err = mdb.SignerLeaveGroup(nil, dbsigner, sp.Signer.SignerGroup)
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

		ss, err := mdb.ListSigners(nil)
		if err != nil {
			log.Printf("Error from ListSigners: %v", err)
		}
		resp.Signers = ss

		// fmt.Printf("APIsigner: resp struct: %v\n", resp)
		// fmt.Printf("APIsigner: resp struct error field: %v\n", resp.Error)

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIsignergroup(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIsignergroup: received /signergroup request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var sgp common.SignerGroupPost
		err := decoder.Decode(&sgp)
		if err != nil {
			log.Println("APIsignergroup: error decoding signergroup post:",
				err)
		}

		var resp = common.SignerGroupResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		fmt.Printf("apiserver: /signergroup %v\n", sgp)

		switch sgp.Command {
		case "list":

		case "add":
			fmt.Printf("apiserver: AddSignerGroup\n")
			msg, err := mdb.AddSignerGroup(nil, sgp.Name)
			if err != nil {
				log.Printf("Error from AddSignerGroup: %v", err)
			}
			resp.Message = msg

		case "delete":
			msg, err := mdb.DeleteSignerGroup(nil, sgp.Name)
			if err != nil {
				log.Printf("Error from DeleteSignerGroup: %v", err)
			}
			resp.Message = msg
		default:

		}

		ss, err := mdb.ListSignerGroups(nil)
		if err != nil {
			log.Printf("Error from ListSignerGroups: %v", err)
		}
		resp.SignerGroups = ss

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIprocess(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	mdb := conf.Internal.MusicDB
	var check common.EngineCheck
	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("APIprocess: received /process request from %s.\n",
			r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp common.ProcessPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIprocess: error decoding process post:", err)
		}

		var resp = common.ProcessResponse{
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

		case "check":
			conf.Internal.EngineCheck <- check
			resp.Msg = "FSM Engine will make a run through all non-blocked zones immediately."

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
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
	}
}

func APIshow(conf *Config, router *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	address := viper.GetString("services.apiserver.api")
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var sp common.ShowPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIshow: error decoding show post:", err)
		}

		log.Printf("APIshow: received /show request (command: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		var resp = common.ShowResponse{
			Status: 101,
		}

		switch sp.Command {
		case "api":
			message := "All ok, here are all defined API endpoints"

			data := []string{fmt.Sprintf("API provided by MUSICD listening on: %s",
				address)}

			walker := func(route *mux.Route, router *mux.Router,
				ancestors []*mux.Route) error {
				path, _ := route.GetPathTemplate()
				methods, _ := route.GetMethods()
				for m := range methods {
					data = append(data, fmt.Sprintf("%-6s %s", methods[m], path))
				}
				return nil
			}
			if err := router.Walk(walker); err != nil {
				log.Panicf("Logging err: %s\n", err.Error())
			}
			resp.Message = message
			resp.ApiData = data

		case "updaters":
			resp.Message = "Defined updaters"
			resp.Updaters = common.ListUpdaters()
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
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
	sr.HandleFunc("/test", APItest(conf)).Methods("POST")
	sr.HandleFunc("/process", APIprocess(conf)).Methods("POST")
	sr.HandleFunc("/show", APIshow(conf, r)).Methods("POST")

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
