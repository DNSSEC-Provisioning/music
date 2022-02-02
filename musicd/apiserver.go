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
	"os"
	"time"

	"github.com/miekg/dns"

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

		apistatus := music.APIstatus{Status: status, Message: resp}
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
		var pp music.PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIping: error decoding ping post:", err)
		}

		pongs += 1

		for i := 1; i < pp.Fetches; i++ {
			conf.Internal.DesecFetch <- music.SignerOp{}
		}
		for i := 1; i < pp.Updates; i++ {
			conf.Internal.DesecUpdate <- music.SignerOp{}
		}

		host, _ := os.Hostname()
		response := music.PingResponse{
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
		var tp music.TestPost
		err := decoder.Decode(&tp)
		if err != nil {
			log.Println("APIzone: error decoding zone post:", err)
		}

		log.Printf("APItest: received /test request (command: %s) from %s.\n",
			tp.Command, r.RemoteAddr)

		var resp = music.TestResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
		}

		w.Header().Set("Content-Type", "application/json")

		switch tp.Command {
		case "dnsquery":
			signer, err := mdb.GetSigner(&music.Signer{Name: tp.Signer}, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			updater := music.GetUpdater(signer.Method)
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
			zs, err := mdb.ListZones()
			if err != nil {
				log.Printf("Error from ListZones: %v", err)
			}
			resp.Zones = zs
		// fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)
		case "status":
			var zl = make(map[string]music.Zone, 1)
			if dbzone.Exists {
				sg, _ := mdb.GetSignerGroup(dbzone.SGname, true)

				zl[dbzone.Name] = music.Zone{
					Name:       dbzone.Name,
					State:      dbzone.State,
					Statestamp: dbzone.Statestamp,
					NextState:  dbzone.NextState,
					FSM:        dbzone.FSM,
					SGroup:     sg,
					SGname:     sg.Name,
				}
				resp.Zones = zl

			} else {
				message := fmt.Sprintf("Zone %s: not in DB", zp.Zone.Name)
				log.Println(message)
				resp.Msg = message
			}

		case "add":
			// err, resp.Msg = mdb.AddZone(dbzone, zp.SignerGroup)
			err, resp.Msg = mdb.AddZone(&zp.Zone, zp.SignerGroup)
			if err != nil {
				// log.Printf("Error from AddZone: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "update":
			// err, resp.Msg = mdb.AddZone(dbzone, zp.SignerGroup)
			err, resp.Msg = mdb.UpdateZone(dbzone, &zp.Zone)
			if err != nil {
				// log.Printf("Error from UpdateZone: %v", err)
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

		// XXX: A single zone cannot "choose" to join an FSM, it's the Group that does that.
		//      This endpoint is only here for development and debugging reasons.
		case "fsm":
			err, resp.Msg = mdb.ZoneAttachFsm(dbzone, zp.FSM, zp.FSMSigner, false)
			if err != nil {
				// log.Printf("Error from ZoneAttachFsm: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "step-fsm":
			// var zones map[string]music.Zone
			// var success bool
			// err, resp.Msg, zones = mdb.ZoneStepFsm(dbzone, zp.FsmNextState)
			// log.Printf("APISERVER: STEP-FSM: Calling ZoneStepFsm for zone %s and %v\n", dbzone.Name, zp.FsmNextState)
			var success bool
			success, err, resp.Msg = mdb.ZoneStepFsm(dbzone, zp.FsmNextState)
			if err != nil {
				log.Printf("APISERVER: Error from ZoneStepFsm: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
				// resp.Zones = zones
				// resp.Zones = map[string]Zone{ dbzone.Name: *dbzone }
				// w.Header().Set("Content-Type", "application/json")
			}
			log.Printf("APISERVER: STEP-FSM: pre GetZone\n")
			dbzone, _ = mdb.ApiGetZone(dbzone.Name) // apisafe
			if !success {
				_, dbzone.StopReason = mdb.ZoneGetMeta(dbzone, "stop-reason")
			}
			resp.Zones = map[string]music.Zone{dbzone.Name: *dbzone}
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
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from Encoder: %v\n", err)
			}
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
			err, resp.Msg = mdb.ZoneSetMeta(dbzone, zp.Metakey, zp.Metavalue)
			if err != nil {
				// log.Printf("Error from ZoneSetMeta: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		default:
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

		dbsigner, _ := mdb.GetSigner(&sp.Signer, false) // not apisafe

		switch sp.Command {
		case "list":
			ss, err := mdb.ListSigners()
			if err != nil {
				log.Printf("Error from GetSigners: %v", err)
			}
			resp.Signers = ss

		case "add":
			err, resp.Msg = mdb.AddSigner(dbsigner, sp.SignerGroup)
			if err != nil {
				// log.Printf("Error from AddSigner: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "update":
			err, resp.Msg = mdb.UpdateSigner(dbsigner, sp.Signer)
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
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
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
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from Encoder: %v\n", err)
		}
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
		err := json.NewEncoder(w).Encode(response)
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
