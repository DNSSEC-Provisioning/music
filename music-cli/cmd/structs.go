/*
 *
 */
package cmd

import (
	"github.com/DNSSEC-Provisioning/music/music"
)

type Config struct {
	Login music.DesecLPost
	API   struct {
		BaseUrl string `validate:"required"`
	}
	Musicd MusicdConf
}

type MusicdConf struct {
	BaseUrl    string `validate:"required"`
	RootCApem  string `validate:"required,file"`
	ApiKey     string `validate:"required"`
	AuthMethod string `validate:"required"`
}
