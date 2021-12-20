//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//
package music

import (
	"database/sql"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/miekg/dns"
)

type CliConfig struct {
	Debug   bool
	Verbose bool
}

type DBUpdate struct {
	Type string
}

type Zone struct {
	Name       string
	Exists     bool // true if zone is present in system
	State      string
	Statestamp time.Time
	NextState  map[string]bool
	StopReason string	// possible reason for a state transition not to be possible
	FSM        string
	SGroup     *SignerGroup
	SGname     string
	MusicDB    *MusicDB
	ZskState   string
}

type SignerGroup struct {
	Name      	string
	SignerMap	map[string]*Signer
	CurrentProcess	string
	PendingRemoval	string
	PendingAddition	string
	NumZones	int
	State     	string
	DB        	*MusicDB
}

func (sg *SignerGroup) Signers() map[string]*Signer {
	return sg.SignerMap
}

type ZoneState string

type Signer struct {
	Name        string
	Exists      bool
	Method      string // "ddns" | "desec" | ...
	Address     string
	Auth        string // AuthDataTmp // TODO: Issue #28
	SignerGroup string  // single signer group for join/leave
	SignerGroups []string // all signer groups signer is member of
	DB          *MusicDB
}

// type AuthDataTmp string // TODO: Issue #28

type AuthData struct {
	TSIGKey    string
	TSIGName   string
	TSIGAlg    string // dns.HmacSHA256, etc
	ApiToken   string
	ApiBaseUrl string `validate:"required" json:"url"`
}

type MusicDB struct {
	mu     sync.Mutex
	db     *sql.DB
        FSMlist	map[string]FSM
	Tokvip *viper.Viper
}

type SignerOp struct {
        Command  string
        Signer   *Signer
        Zone     string
        Owner    string
        RRtype   uint16
        Inserts  *[][]dns.RR
        Removes  *[][]dns.RR
        Response chan SignerOpResult
}

type SignerOpResult struct {
        Status   int
	Rcode	 uint8      // only relevant for DDNS
        RRs      []dns.RR
        Error    error
        Response string
}
