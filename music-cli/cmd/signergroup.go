/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	music "github.com/DNSSEC-Provisioning/music/common"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var sgroupname string

var signerGroupCmd = &cobra.Command{
	Use:   "signergroup",
	Short: "Signer group commands",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var addSignerGroupCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new signer group to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		sgr := SendSignerGroupCmd(sgroupname, music.SignerGroupPost{
			Command: "add",
			Name:    sgroupname,
		})
		if sgr.Message != "" {
			fmt.Printf("%s\n", sgr.Message)
		}
	},
}

var deleteSignerGroupCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a signer group from MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		data := music.SignerGroupPost{
			Command: "delete",
			Name:    sgroupname,
		}

		sgr := SendSignerGroupCmd(sgroupname, data)
		if sgr.Message != "" {
			fmt.Printf("%s\n", sgr.Message)
		}
	},
}

var listSignerGroupsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all signer groups known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		sgr := SendSignerGroupCmd("none", music.SignerGroupPost{
			Command: "list",
		})
		PrintSignerGroups(sgr)
	},
}

func init() {
	rootCmd.AddCommand(signerGroupCmd)
	signerGroupCmd.AddCommand(addSignerGroupCmd, deleteSignerGroupCmd, listSignerGroupsCmd)
}

func SendSignerGroupCmd(group string, data music.SignerGroupPost) music.SignerGroupResponse {
	if group == "" {
		log.Fatalf("Signer group must be specified.\n")
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signergroup", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("SendSignerGroupCmd: Error from APIpost: %v\n", err)
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sgr music.SignerGroupResponse
	err = json.Unmarshal(buf, &sgr)
	if err != nil {
		log.Fatalf("SendSignerGroupCmd: Error from unmarshal: %v\n", err)
	}

	return sgr
}

func PrintSignerGroups(sgr music.SignerGroupResponse) {
	if len(sgr.SignerGroups) > 0 {
		var out []string
		if cliconf.Verbose || showheaders {
			out = append(out, "Group|Locked|Signers|# Zones|# Proc Zones|Current Process|PendingAddition|PendingRemoval")
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
			out = append(out, fmt.Sprintf("%s|%v|%s|%d|%d|%s|%s|%s", k, v.Locked, ss,
				v.NumZones, v.NumProcessZones, cp, pa, pr))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}
±