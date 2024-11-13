/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package mcmd

import (
	"github.com/DNSSEC-Provisioning/music/music"
	"github.com/spf13/viper"
	"github.com/go-playground/validator/v10"
)

var cfgFile, Zonename, Signername, Sgroupname string
var Showheaders bool

var tokvip *viper.Viper
var cliconf = music.CliConfig{}
var api *music.Api

var validate *validator.Validate

