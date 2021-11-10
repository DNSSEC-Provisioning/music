//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//
package music

import (
    "database/sql"
    "github.com/spf13/viper"
    "sync"
    "time"
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
    State      string
    Statestamp time.Time
    NextState  map[string]bool
    FSM        string
    sgroup     *SignerGroup
    SGname     string
    MusicDB    *MusicDB
    ZskState   string
}

type SignerGroup struct {
    Name      string
    SignerMap map[string]Signer
    State     string
    DB        *MusicDB
}

type GormSignerGroup struct {
    Name      string
    SignerMap []Signer
    State     string
    DB        *MusicDB
}

func (sg *SignerGroup) Signers() map[string]Signer {
    return sg.SignerMap
}

type ZoneState string

type Signer struct {
    Name        string
    Method      string // "ddns" | "desec" | ...
    Address     string
    Auth        string // AuthDataTmp // TODO: Issue #28
    SignerGroup string
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
    Tokvip *viper.Viper
}
