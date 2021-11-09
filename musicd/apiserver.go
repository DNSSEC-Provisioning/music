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

    "github.com/miekg/dns"

    "github.com/DNSSEC-Provisioning/music/common"

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

        log.Printf("APIsigner: received /zone request (command: %s) from %s.\n",
            zp.Command, r.RemoteAddr)

        var resp = music.ZoneResponse{
            Time:   time.Now(),
            Client: r.RemoteAddr,
        }

        dbzone, exist := mdb.GetZone(zp.Zone.Name) // Get a more complete Zone structure
        // fmt.Printf("APIzone: zp.Zone.Name: %s dbzone.Name: %s\n", zp.Zone.Name, dbzone.Name)

        switch zp.Command {
        case "list":

        case "add":
            err, resp.Msg = mdb.AddZone(&zp.Zone, zp.SignerGroup)
            if err != nil {
                // log.Printf("Error from AddZone: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "delete":
            err, resp.Msg = mdb.DeleteZone(zp.Zone.Name, dbzone, exist)
            if err != nil {
                // log.Printf("Error from DeleteZone: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "join":
            err, resp.Msg = mdb.ZoneJoinGroup(zp.Zone.Name, dbzone, exist,
                zp.SignerGroup)
            if err != nil {
                // log.Printf("Error from ZoneJoinGroup: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "leave":
            err, resp.Msg = mdb.ZoneLeaveGroup(zp.Zone.Name, dbzone, exist,
                zp.SignerGroup)
            if err != nil {
                // log.Printf("Error from ZoneLeaveGroup: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "fsm":
            err, resp.Msg = mdb.ZoneAttachFsm(zp.Zone.Name, dbzone, exist, zp.FSM)
            if err != nil {
                // log.Printf("Error from ZoneAttachFsm: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "step-fsm":
            var zones map[string]music.Zone
            err, resp.Msg, zones = mdb.ZoneStepFsm(zp.Zone.Name, dbzone,
                exist, zp.FsmNextState)
            if err != nil {
                // log.Printf("Error from ZoneStepFsm: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
                resp.Zones = zones
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(resp)
                return
            }

        case "get-rrsets":
            // fmt.Printf("APIzone: get-rrset: %s %s %s\n", zp.Zone.Name, zp.Owner, zp.RRtype)
            var rrsets map[string][]dns.RR
            err, resp.Msg, rrsets = mdb.ZoneGetRRsets(zp.Zone.Name, dbzone,
                exist, zp.Owner, zp.RRtype)
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
                    err, resp.Msg, rrset = mdb.ListRRset(zp.Zone.Name, k, zp.Owner, zp.RRtype)
                    if err != nil {
                        log.Fatalf("APIzone: get-rrsets: Error from ListRRset: %v\n", err)
                    } else {
                        result[k] = rrset
                    }
                }
                resp.RRsets = result
                fmt.Printf("get:rrsets: len: %d\n", len(rrsets))
                //                switch dns.StringToType[zp.RRtype] {
                //                case dns.TypeDNSKEY:
                //                     resp.DNSKEYs = map[string][]dns.DNSKEY(rrsets)
                //                case dns.TypeSOA:
                //                     resp.SOAs = map[string][]dns.SOA(rrsets)
                //                case dns.TypeNS:
                //                     resp.NSs = map[string][]dns.NS(rrsets)
                //                }
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(resp)
            return

        case "copy-rrset":
            fmt.Printf("APIzone: copy-rrset: %s %s %s\n", zp.Zone.Name, zp.Owner, zp.RRtype)
            // var rrset []dns.RR
            err, resp.Msg = mdb.ZoneCopyRRset(zp.Zone.Name, dbzone,
                exist, zp.Owner, zp.RRtype,
                zp.FromSigner, zp.ToSigner)
            if err != nil {
                log.Printf("Error from ZoneCopyRRset: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            } else {
                // resp.RRset = rrset
                // fmt.Printf("copy:rrset: len: %d\n", len(rrset))
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(resp)
            return

        case "list-rrset":
            var rrset []string
            err, resp.Msg, rrset = mdb.ListRRset(zp.Zone.Name, zp.Signer, zp.Owner, zp.RRtype)
            if err != nil {
                log.Printf("Error from ListRRset: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            } else {
                resp.RRset = rrset
                //                resp.Test = map[string][]string{
                //                        "foo":    { "bar", "bar2"},
                //                        "bar":    { "foo", "foo2"},
                //                        }
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(resp)
            return

        default:
        }

        zs, err := mdb.ListZones()
        if err != nil {
            log.Printf("Error from ListZones: %v", err)
        }
        resp.Zones = zs

        // fmt.Printf("\n\nAPIzone: resp: %v\n\n", resp)

        w.Header().Set("Content-Type", "application/json")
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

        var dbsigner music.Signer

        if sp.Command != "list" {
            dbsigner, err = mdb.GetSigner(sp.Signer.Name)
        }

        switch sp.Command {
        case "list":

        case "add":
            err, resp.Msg = mdb.AddSigner(sp.Signer)
            if err != nil {
                // log.Printf("Error from AddSigner: %v", err)
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
            err, resp.Msg = mdb.SignerJoinGroup(sp.Signer, sp.Signer.SignerGroup)
            if err != nil {
                // log.Printf("Error from SignerJoinGroup: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "leave":
            err, resp.Msg = mdb.SignerLeaveGroup(sp.Signer, sp.Signer.SignerGroup)
            if err != nil {
                // log.Printf("Error from SignerLeaveGroup: %v", err)
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "login":
            err, resp.Msg = mdb.SignerLogin(&dbsigner, &cliconf, tokvip)
            if err != nil {
                resp.Error = true
                resp.ErrorMsg = err.Error()
            }

        case "logout":
            err, resp.Msg = mdb.SignerLogout(&dbsigner, &cliconf, tokvip)
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
            log.Println("APIsignergroup: error decoding signer post:",
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

    if address != "" {
        log.Println("Starting API dispatcher. Listening on", address)
        log.Fatal(http.ListenAndServe(address, router))
    }

    log.Println("API dispatcher: unclear how to stop the http server nicely.")
    return nil
}
