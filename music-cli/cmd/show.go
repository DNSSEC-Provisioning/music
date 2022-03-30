/*
 *
 */
package cmd

import (
        "bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
	music "github.com/DNSSEC-Provisioning/music/common"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "A brief description of your command",
}

var showUpdatersCmd = &cobra.Command{
	Use:   "updaters",
	Short: "List the updaters known to musicd",
	Run: func(cmd *cobra.Command, args []string) {
		sr := SendShowCommand(music.ShowPost{ Command: "updaters"})
		for u, v := range sr.Updaters {
		    if v {
		       fmt.Printf("%s\n", u)
		    }
		}
	},
}

var showApiCmd = &cobra.Command{
	Use:   "api",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		sr := SendShowCommand(music.ShowPost{ Command: "api"})
		for _, l := range sr.ApiData {
		    fmt.Printf("%s\n", l)
		}
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.AddCommand(showApiCmd, showUpdatersCmd)
}

func SendShowCommand(data music.ShowPost) music.ShowResponse {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)
	status, buf, err := api.Post("/show", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("SendShowCommand: Error from api.Post: %v", err)

	}
	if cliconf.Debug {
		fmt.Println()
		fmt.Printf("SendShowCommand Status: %d\n", status)
	}

	var sr music.ShowResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v", err)
	}
	return sr
}
