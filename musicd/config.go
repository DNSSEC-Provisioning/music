/*
 * Johan Stenstam
 */
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/spf13/viper"
	"github.com/go-playground/validator/v10"

	"github.com/DNSSEC-Provisioning/music/common"
)

var cfgFile string
var verbose bool

type Config struct {
	ApiServer ApiServerConf
	Signers   []SignerConf
	Common    CommonConf
	Internal  InternalConf
}

type ApiServerConf struct {
	Address  string `validate:"required,hostname_port"`
	CertFile string `validate:"required,file"`
	KeyFile  string `validate:"required,file"`
	UseTLS   bool
}

type SignerConf struct {
	Name    string
	Address string `validate:"hostname_port"`
	BaseURL string `validate:"url"`
	Method  string // ddns | desec | ...
	Auth    string // tsig | userpasstoken
	Tsig    TsigConf
	Limits	RateLimitsConf
}

type RateLimitsConf struct {
        Fetch	    int // get rrset ops / second
        Update	    int // update rrset ops / second
}

type TsigConf struct {
	KeyName   string `dns:"domain-name"`
	KeyAlg    string // dns.HmacSHA256 is most common
	KeySecret string
}

type CommonConf struct {
	DB        string `validate:"file"`
	TokenFile string `validate:"file,required"`
	//    GormDB  string   `validate:"file"`
	//    Command string   `validate:"file"`
}

// Internal stuff that we want to be able to reach via the Config struct, but are not
// represented in the yaml config file.
type InternalConf struct {
	DBUpdateCh chan music.DBUpdate
	APIStopCh  chan struct{}
	DB         *sql.DB
	MusicDB    *music.MusicDB
	TokViper   *viper.Viper
	DesecFetch chan DesecOp
	DesecUpdate chan DesecOp
}

func ValidateConfig(v *viper.Viper, cfgfile string, safemode bool) error {
	var config Config
	var msg string

	if safemode {
		if v == nil {
			return errors.New("ValidateConfig: cannot use safe mode with nil viper")
		} else {
			if err := v.Unmarshal(&config); err != nil {
				msg = fmt.Sprintf("ValidateConfig: unable to unmarshal the config %v",
					err)
				return errors.New(msg)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			msg = fmt.Sprintf("ValidateConfig: \"%s\" is missing required attributes:\n%v\n",
				cfgfile, err)
			return errors.New(msg)
		}
	} else {
		if v == nil {
			if err := viper.Unmarshal(&config); err != nil {
				log.Fatalf("unable to unmarshal the config %v", err)
			}
		} else {
			if err := v.Unmarshal(&config); err != nil {
				log.Fatalf("unable to unmarshal the config %v", err)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
		}
		// fmt.Printf("config: %v\n", config)
	}
	return nil
}
