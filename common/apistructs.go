//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//
package music

import (
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type APIstatus struct {
	Status  int
	Message string
}

type APIresponse struct {
	Status  int
	Message string
	Data    string
}

type ShowAPIresponse struct {
	Status  int
	Message string
	Data    []string
}

type PingPost struct {
	Message string
	Pings   int
	Fetches	int
	Updates	int
}

type PingResponse struct {
	Time    time.Time
	Client  string
	Message string
	Pings   int
	Pongs   int
}

type ZonePost struct {
	Command      string
	Zone         Zone
	Owner        string
	RRtype       string
	Signer       string // debug
	FromSigner   string
	ToSigner     string
	SignerGroup  string
	FSM          string
	FsmNextState string
	Metakey      string
	Metavalue    string
}

type DNSRecords []dns.RR

type ZoneResponse struct {
	Time     time.Time
	Status   int
	Client   string
	Error    bool
	ErrorMsg string
	// Message        string
	Msg    string
	Zones  map[string]Zone
	RRsets map[string][]string // map[signer][]DNSRecords
	RRset  []string            // broken
}

type SignerPost struct {
	Command string
	Signer  Signer
}

type SignerResponse struct {
	Time     time.Time
	Status   int
	Client   string
	Error    bool
	ErrorMsg string
	Msg      string
	Signers  map[string]Signer
}

type SignerGroupPost struct {
	Command string
	Name    string
}

type SignerGroupResponse struct {
	Time         time.Time
	Status       int
	Client       string
	Message      string
	SignerGroups map[string]SignerGroup
}

type Api struct {
	Client     *http.Client
	Apiurl     string
	apiKey     string
	Authmethod string
	Verbose    bool
	Debug      bool
}

type ProcessPost struct {
	Command string
	Process string
}

type ProcessResponse struct {
	Time      time.Time
	Status    int
	Client    string
	Error     bool
	ErrorMsg  string
	Msg       string
	Processes []Process
	Graph     string
}

type Process struct {
	Name string
	Desc string
}
