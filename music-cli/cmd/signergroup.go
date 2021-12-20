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
		data := music.SignerGroupPost{
			Command: "add",
			Name:    sgroupname,
		}

		sgr, err := SendSignerGroupCommand(sgroupname, data)
		if err != nil {
			fmt.Printf("Error from SendSignerGroupCommand: %v\n", err)
		}
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

		sgr, err := SendSignerGroupCommand(sgroupname, data)
		if err != nil {
			fmt.Printf("Error from SendSignerGroupCommand: %v\n", err)
		}
		if sgr.Message != "" {
			fmt.Printf("%s\n", sgr.Message)
		}
	},
}

var listSignerGroupsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all signer groups known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		data := music.SignerGroupPost{
			Command: "list",
		}

		sgr, err := SendSignerGroupCommand("none", data)
		if err != nil {
			fmt.Printf("Error from ListSignerGroups: %v\n", err)
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
	},
}

func init() {
	rootCmd.AddCommand(signerGroupCmd)
	signerGroupCmd.AddCommand(addSignerGroupCmd, deleteSignerGroupCmd, listSignerGroupsCmd)

	// note that this is a root flag, to make it available to both "signer" and "signergroup"
	rootCmd.PersistentFlags().StringVarP(&sgroupname, "group", "g",
		"", "name of signer group")
}

func SendSignerGroupCommand(group string, data music.SignerGroupPost) (music.SignerGroupResponse, error) {
	var sgr music.SignerGroupResponse

	if group == "" {
		log.Fatalf("Signer group must be specified.\n")
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signergroup", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return sgr, err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &sgr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	// fmt.Printf("Data from /signergroup add: %v\n",
	return sgr, nil
}

func xxxAddSignerGroup() error {
	data := music.SignerGroupPost{
		Command: "add",
		Name:    sgroupname,
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signergroup", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerGroupResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	// fmt.Printf("Data from /signergroup add: %v\n", sr)
	return nil
}

func xxxDeleteSignerGroup() error {
	data := music.SignerGroupPost{
		Command: "delete",
		Name:    sgroupname,
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signergroup", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerGroupResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	// fmt.Printf("Data from /signergroup delete: %v\n", sr)
	return nil
}

func ListSignerGroups() error {
	data := music.SignerGroupPost{
		Command: "list",
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signergroup", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerGroupResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	// fmt.Printf("Data from /signergroup list: %v\n", sr)

	var out []string
	if cliconf.Verbose || showheaders {
		out = append(out, "Name of signergroup|Signers in group")
	}

	for k, v := range sr.SignerGroups {
		var ss string
		for k1, _ := range v.SignerMap {
			ss += fmt.Sprintf(", %s", k1)
		}
		if len(ss) > 2 {
			ss = ss[1:]
		}
		out = append(out, fmt.Sprintf("%s|%s", k, ss))
	}
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
	return nil
}
