/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "sort"
    "strings"

    "github.com/DNSSEC-Provisioning/music/common"

    "github.com/miekg/dns"
    "github.com/ryanuber/columnize"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var fsmname, fsmnextstate, ownername, rrtype, fromsigner, tosigner string

var zoneCmd = &cobra.Command{
    Use:   "zone",
    Short: "Zone commands",
    Run: func(cmd *cobra.Command, args []string) {
    },
}

var addZoneCmd = &cobra.Command{
    Use:   "add",
    Short: "Add a new zone to MuSiC",
    Run: func(cmd *cobra.Command, args []string) {
        err := AddZone(dns.Fqdn(zonename), sgroupname) // for addzone it is ok if sgroupname==""
        if err != nil {
            fmt.Printf("Error from AddZone: %v\n", err)
        }
    },
}

var zoneJoinGroupCmd = &cobra.Command{
    Use:   "join",
    Short: "Join a zone to a signer group",
    Run: func(cmd *cobra.Command, args []string) {
        _, _ = ZoneJoinGroup(dns.Fqdn(zonename), sgroupname)
    },
}

var zoneLeaveGroupCmd = &cobra.Command{
    Use:   "leave",
    Short: "Remove a zone from a signer group",
    Run: func(cmd *cobra.Command, args []string) {
        _, _ = ZoneLeaveGroup(dns.Fqdn(zonename), sgroupname)
    },
}

var deleteZoneCmd = &cobra.Command{
    Use:   "delete",
    Short: "Delete a zone from MuSiC",
    Run: func(cmd *cobra.Command, args []string) {
        err := DeleteZone()
        if err != nil {
            fmt.Printf("Error from DeleteZone: %v\n", err)
        }
    },
}

var zoneFsmCmd = &cobra.Command{
    Use:   "fsm",
    Short: "Insert zone into an FSM",
    Long: `Inserting a zone into a FSM will cause it to start a set of transitions
from one state to the next under control of specific criteria for each
transition. At each stage the current state is presented and manual
transition may be initiated with the 'music-cli zone step -z {zone}'
command.`,
    Run: func(cmd *cobra.Command, args []string) {
        failure, _ := ZoneFsm(dns.Fqdn(zonename), fsmname)
        if failure {
            // fmt.Printf("Error: %s\n", errmsg)
        }
    },
}

var zoneStepFsmCmd = &cobra.Command{
    Use:   "step-fsm",
    Short: "Try to make the zone transition from one state to the next in the FSM",
    Run: func(cmd *cobra.Command, args []string) {
        failure, _, zm := ZoneStepFsm(dns.Fqdn(zonename))
        if failure {
            // fmt.Printf("Error: %s\n", errmsg)
        } else {
            PrintZones(zm)
        }
    },
}

var zoneGetRRsetsCmd = &cobra.Command{
    Use:   "get-rrsets",
    Short: "Retrieve an rrset from the signers in the signer group for this zone",
    Run: func(cmd *cobra.Command, args []string) {
        failure, errmsg, rrsets := ZoneGetRRsets(dns.Fqdn(zonename), dns.Fqdn(ownername), rrtype)
        if failure {
            fmt.Printf("Error: %s\n", errmsg)
        } else {
            PrintRRsets(rrsets)
        }
    },
}

var zoneListRRsetCmd = &cobra.Command{
    Use:   "list-rrset",
    Short: "Retrieve an rrset from the db for one signer in the signer group for this zone (debug)",
    Run: func(cmd *cobra.Command, args []string) {
        failure, errmsg, rrset := ZoneListRRset(dns.Fqdn(zonename),
            dns.Fqdn(ownername), rrtype, signername)
        if failure {
            fmt.Printf("Error: %s\n", errmsg)
        } else {
            PrintRRset(rrset)
        }
    },
}

var zoneCopyRRsetCmd = &cobra.Command{
    Use:   "copy-rrset",
    Short: "Copy an rrset from one signer in the signer group to another",
    Run: func(cmd *cobra.Command, args []string) {
        failure, errmsg, rrset := ZoneCopyRRset(dns.Fqdn(zonename),
            dns.Fqdn(ownername), rrtype, signername)
        if failure {
            fmt.Printf("Error: %s\n", errmsg)
        } else {
            PrintRRset(rrset)
        }
    },
}

var listZonesCmd = &cobra.Command{
    Use:   "list",
    Short: "List all zones known to MuSiC",
    Run: func(cmd *cobra.Command, args []string) {
        zr, err := ListZones()
        if err != nil {
            fmt.Printf("Error from ListZones: %v\n", err)
        } else {
            PrintZones(zr)
        }
    },
}

func init() {
    rootCmd.AddCommand(zoneCmd)
    zoneCmd.AddCommand(addZoneCmd, deleteZoneCmd, listZonesCmd, zoneJoinGroupCmd,
        zoneLeaveGroupCmd, zoneFsmCmd, zoneStepFsmCmd,
        zoneGetRRsetsCmd, zoneListRRsetCmd, zoneCopyRRsetCmd)

    zoneFsmCmd.Flags().StringVarP(&fsmname, "fsm", "f", "", "name of finite state machine to attach zone to")
    zoneStepFsmCmd.Flags().StringVarP(&fsmnextstate, "nextstate", "", "", "name of next state in on-going FSM process")
    zoneCopyRRsetCmd.Flags().StringVarP(&fromsigner, "from", "", "", "name of signer to copy from")
    zoneCopyRRsetCmd.Flags().StringVarP(&tosigner, "to", "", "", "name of signer to copy to")
    zoneCmd.PersistentFlags().StringVarP(&ownername, "owner", "o", "", "DNS owner name of RRset")
    zoneCmd.PersistentFlags().StringVarP(&rrtype, "rrtype", "r", "", "RRtype of RRset")
}

func AddZone(zonename, sgroup string) error {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    // IsDomainName() is too liberal, we need a stricter test.
    if _, ok := dns.IsDomainName(zonename); !ok {
        log.Fatalf("AddZone: Error: '%s' is not a legal domain name. Terminating.\n", zonename)
    }

    data := music.ZonePost{
        Command: "add",
        Zone: music.Zone{
            Name: zonename,
        },
        SignerGroup: sgroup,
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return err
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return nil
}

func ZoneFsm(zone, fsm string) (bool, string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if zone == "" {
        log.Fatalf("ZoneFsm: zone not specified. Terminating.\n")
    }

    if fsm == "" {
        log.Fatalf("ZoneFsm: FSM not specified. Terminating.\n")
    }

    data := music.ZonePost{
        Command: "fsm",
        Zone: music.Zone{
            Name: zone,
        },
        FSM: fsm,
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key", bytebuf.Bytes(),
        false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error()
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return zr.Error, zr.ErrorMsg
}

func ZoneStepFsm(zone string) (bool, string, map[string]music.Zone) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if zone == "" {
        log.Fatalf("ZoneStepFsm: zone not specified. Terminating.\n")
    }

    zm, err := ListZones()
    if err != nil {
        log.Fatalf("ZoneStepFsm: Error from ListZones: %v\n", err)
    }

    fsm := zm[zone].FSM

    if fsm == "" || fsm == "none" {
        log.Fatalf("ZoneStepFsm: Zone %s is not attached to any FSM. Terminating.\n", zone)
    }

    data := music.ZonePost{
        Command: "step-fsm",
        Zone: music.Zone{
            Name: zone,
        },
        FsmNextState: fsmnextstate,
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key", bytebuf.Bytes(),
        false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error(), map[string]music.Zone{}
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return zr.Error, zr.ErrorMsg, zr.Zones
}

func ZoneJoinGroup(zone, group string) (bool, string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if zone == "" {
        log.Fatalf("ZoneJoinGroup: zone not specified. Terminating.\n")
    }

    if group == "" {
        log.Fatalf("ZoneJoinGroup: signer group not specified. Terminating.\n")
    }

    data := music.ZonePost{
        Command: "join",
        Zone: music.Zone{
            Name: zone,
        },
        SignerGroup: group,
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error()
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return zr.Error, zr.ErrorMsg
}

func ZoneLeaveGroup(zone, group string) (bool, string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if zone == "" {
        log.Fatalf("ZoneLeaveGroup: zone not specified. Terminating.\n")
    }

    if group == "" {
        log.Fatalf("ZoneLeaveGroup: signer group not specified. Terminating.\n")
    }

    data := music.ZonePost{
        Command: "leave",
        Zone: music.Zone{
            Name: zone,
        },
        SignerGroup: group,
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key", bytebuf.Bytes(),
        false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error()
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return zr.Error, zr.ErrorMsg
}

func DeleteZone() error {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    data := music.ZonePost{
        Command: "delete",
        Zone: music.Zone{
            Name: dns.Fqdn(zonename),
        },
    }
    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return err
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return nil
}

func ListZones() (map[string]music.Zone, error) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    data := music.ZonePost{
        Command: "list",
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return map[string]music.Zone{}, err
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr music.ZoneResponse
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return zr.Zones, nil
}

func ZoneGetRRsets(zone, owner, rrtype string) (bool, string, map[string][]string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if !strings.HasSuffix(owner, zone) {
        fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", zone, owner)
        os.Exit(1)
    }

    data := music.ZonePost{
        Command: "get-rrsets",
        Zone: music.Zone{
            Name: zone,
        },
        Owner:  owner,
        RRtype: strings.ToUpper(rrtype),
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error(), map[string][]string{}
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr = music.ZoneResponse{
        Zones:  map[string]music.Zone{},
        RRsets: map[string][]string{},
    }
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("ZoneGetRRsets: Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return false, "", zr.RRsets
}

func ZoneListRRset(zone, owner, rrtype, signer string) (bool, string, []string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if !strings.HasSuffix(owner, zone) {
        fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", zone, owner)
        os.Exit(1)
    }

    data := music.ZonePost{
        Command: "list-rrset",
        Zone: music.Zone{
            Name: zone,
        },
        Owner:  owner,
        RRtype: strings.ToUpper(rrtype),
        Signer: signername,
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error(), []string{}
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr = music.ZoneResponse{
        Zones:  map[string]music.Zone{},
        RRsets: map[string][]string{},
    }
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("ZoneListRRset: Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return false, "", zr.RRset
}

func ZoneCopyRRset(zone, owner, rrtype, signer string) (bool, string, []string) {
    apiurl := viper.GetString("musicd.baseurl") + "/zone"
    apikey := viper.GetString("musicd.apikey")

    if !strings.HasSuffix(owner, zone) {
        fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", zone, owner)
        os.Exit(1)
    }

    data := music.ZonePost{
        Command: "copy-rrset",
        Zone: music.Zone{
            Name: zone,
        },
        Owner:      owner,
        RRtype:     strings.ToUpper(rrtype),
        Signer:     signername,
        FromSigner: fromsigner,
        ToSigner:   tosigner,
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
        bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
    if err != nil {
        log.Println("Error from GenericAPIpost:", err)
        return true, err.Error(), []string{}
    }
    if cliconf.Debug {
        fmt.Printf("Status: %d\n", status)
    }

    var zr = music.ZoneResponse{
        Zones:  map[string]music.Zone{},
        RRsets: map[string][]string{},
    }
    err = json.Unmarshal(buf, &zr)
    if err != nil {
        log.Fatalf("ZoneListRRset: Error from unmarshal: %v\n", err)
    }

    PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
    return false, "", zr.RRset
}

// Is this actually exactly the same as PrintSignerResponse?
func PrintZoneResponse(iserr bool, errormsg, msg string) {
    if iserr {
        fmt.Printf("%s\n", errormsg)
    }

    if msg != "" {
        fmt.Printf("%s\n", msg)
    }
}

func PrintZones(zm map[string]music.Zone) {
    var out []string
    var zone music.Zone

    if cliconf.Verbose {
        // out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Possible Next State(s)|ZSK State")
        out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Next State(s)|ZSK State")
    }

    zonenames := make([]string, 0, len(zm))
    for k := range zm {
        zonenames = append(zonenames, k)
    }
    sort.Strings(zonenames)

    for _, zn := range zonenames {
        zone = zm[zn]
        group := "---"
        // if zone.SignerGroup().Name != "" {
        if zone.SGname != "" {
            group = zone.SGname
        }

        fsm := "---"
        if zone.FSM != "" {
            fsm = zone.FSM
        }

        if zone.State == "" {
            zone.State = "---"
        }

        if zone.ZskState == "" {
            zone.ZskState = "---"
        }

        nextStates := []string{}
        for k, _ := range zone.NextState {
            nextStates = append(nextStates, k)
        }
        out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|[%s]|%s", zone.Name, group, fsm,
            zone.State, zone.Statestamp.Format("2006-01-02 15:04:05"),
            strings.Join(nextStates, " "), zone.ZskState))
    }
    fmt.Printf("%s\n", columnize.SimpleFormat(out))
}

func PrintRRsets(msrrs map[string][]string) {
    for signer, rrs := range msrrs {
        fmt.Printf("Data from signer: %s:\n", signer)
        PrintRRset(rrs)
    }
}

func PrintRRset(rrset []string) {
    var out []string
    var row string

    if cliconf.Verbose {
        out = append(out, fmt.Sprintf("Owner|Class|Type|Rdata"))
    }

    for _, r := range rrset {
        rr, err := dns.NewRR(r)
        if err != nil {
            fmt.Printf("RR '%s' failed to parse. Error: %v\n", r, err)
        } else {
            // switch dns.StringToType[rrtype] {
            switch rr.(type) {
            case *dns.DNSKEY:
                row = fmt.Sprintf("%s|IN|DNSKEY|%d %d %d|%s...%s",
                    rr.(*dns.DNSKEY).Header().Name,
                    rr.(*dns.DNSKEY).Flags,
                    rr.(*dns.DNSKEY).Protocol,
                    rr.(*dns.DNSKEY).Algorithm,
                    rr.(*dns.DNSKEY).PublicKey[0:30],
                    rr.(*dns.DNSKEY).PublicKey[len(rr.(*dns.DNSKEY).PublicKey)-30:])
            default:

                parts := strings.Split(rr.String(), "\t")
                parts = parts[4:]
                rdata := strings.Join(parts, " ")
                row = fmt.Sprintf("%s|IN|%s|%s", rr.Header().Name,
                    dns.TypeToString[rr.Header().Rrtype], rdata)
            }
        }
        out = append(out, row)
    }
    fmt.Printf("%s\n", columnize.SimpleFormat(out))
}
