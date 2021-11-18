/*
 *
 */
package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	music "github.com/DNSSEC-Provisioning/music/common"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "A brief description of your command",
	//    Run: func(cmd *cobra.Command, args []string) {
	//        fmt.Println("show called")
	//    },
}

var showApiCmd = &cobra.Command{
	Use:   "api",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		ShowMusicdApi()
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.AddCommand(showApiCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// showCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// showCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func ShowMusicdApi() {

	status, buf, err := api.Get("/show/api")
	if err != nil {
		log.Println("Error from Api Get:", err)
		return
	}
	if cliconf.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var sar music.ShowAPIresponse
	err = json.Unmarshal(buf, &sar)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	for _, l := range sar.Data {
		fmt.Printf("%s\n", l)
	}
	return
}
