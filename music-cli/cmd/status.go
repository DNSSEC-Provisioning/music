/*
* Rog Murray, roger.murray@internetstiftelsen.se
 */
package cmd

import (
	music "github.com/DNSSEC-Provisioning/music/common"
)

func ZoneStatus() {
	zone := "fluffmunk.se." // must have something, not used
	zr := SendZoneCommand(zone, music.ZonePost{
		Command: "list",
		Zone: music.Zone{
			Name: zone,
		},
	})
	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	PrintZones(zr.Zones)
}

func SignerStatus() {
	sr := SendSignerCmd(music.SignerPost{
		Command: "list",
	})
	PrintSigners(sr)
}

func SignerGroupStatus() {
	sgr := SendSignerGroupCmd("none", music.SignerGroupPost{
		Command: "list",
	})
	PrintSignerGroups(sgr)
}
