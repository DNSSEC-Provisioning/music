/*
* Rog Murray, roger.murray@internetstiftelsen.se
 */
package cmd

import (
	"fmt"

	music "github.com/DNSSEC-Provisioning/music/common"
	"github.com/ryanuber/columnize"
)

func ZoneStatus() {
	zone := "fluffmunk.se." // must have something, not used
	data := music.ZonePost{
		Command: "list",
		Zone: music.Zone{
			Name: zone,
		},
	}
	zr, err := SendZoneCommand(zone, data)
	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	if err != nil {
		fmt.Printf("Error from ListZones: %v\n", err)
	} else {
		PrintZones(zr.Zones)
	}
}

func SignerStatus() {
	ListSigners()
}

func SignerGroupStatus() {
	data := music.SignerGroupPost{
		Command: "list",
	}
	sgr, err := SendSignerGroupCommand("none", data)
	if err != nil {
		fmt.Printf("Error from SendSignerGroupCommand: %v\n", err)
	}
	if len(sgr.SignerGroups) > 0 {
		var out []string
		if cliconf.Verbose || showheaders {
			out = append(out, "Group name|Signers in group|Zones|Current Process|PendingAddition|PendingRemoval")
		}

		for k, v := range sgr.SignerGroups {
			var ss string
			for k1, _ := range v.SignerMap {
				ss += fmt.Sprintf(", %s", k1)
			}
			if len(ss) > 2 {
				ss = ss[1:]
			}
			cp := v.CurrentProcess
			if cp == "" {
				cp = "---"
			}
			pa := v.PendingAddition
			if pa == "" {
				pa = "---"
			}
			pr := v.PendingRemoval
			if pr == "" {
				pr = "---"
			}
			out = append(out, fmt.Sprintf("%s|%s|%d|%s|%s|%s", k, ss, v.NumZones, cp, pa, pr))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}
