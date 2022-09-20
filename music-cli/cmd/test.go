/*
 *
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	// "github.com/ryanuber/columnize"

	// "github.com/go-playground/validator/v10"

	"github.com/DNSSEC-Provisioning/music/music"
)

var testcount int

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "send API requests to MUSICD that are intended for debugging purposes",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("test called")
	},
}

var testDnsQueryCmd = &cobra.Command{
	Use:   "dnsquery",
	Short: "send DNS queries directly via MUSICD without involving a MUSIC process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("dnsquery called")

		zone := dns.Fqdn(zonename)

		data := music.TestPost{
			Command: "dnsquery",
			Signer:  signername,
			Qname:   dns.Fqdn(ownername),
			RRtype:  rrtype,
			Count:   testcount,
		}

		tr, _ := SendTestCommand(zone, data)
		if tr.Error {
			fmt.Printf("Error: %s\n", tr.ErrorMsg)
		}
		fmt.Printf("TestResponse: %v\n", tr)
	},
}

var testDnsUpdateCmd = &cobra.Command{
	Use:   "dnsupdate",
	Short: "send DNS updates directly via MUSICD without involving a MUSIC process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("dnsupdate called")
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(testDnsQueryCmd, testDnsUpdateCmd)

	testCmd.PersistentFlags().StringVarP(&ownername, "owner", "o", "", "DNS owner name (FQDN)")
	testCmd.PersistentFlags().StringVarP(&rrtype, "rrtype", "r", "", "DNS RRtype")
	// testCmd.PersistentFlags().StringVarP(&signername, "signer", "s", "", "MUSIC signer")
	testCmd.PersistentFlags().IntVarP(&testcount, "count", "c", 1, "Test count")
}

func SendTestCommand(zone string, data music.TestPost) (music.TestResponse, error) {
	// IsDomainName() is too liberal, we need a stricter test.
	if _, ok := dns.IsDomainName(zonename); !ok {
		log.Fatalf("SendZoneCommand: Error: Zone '%s' is not a legal domain name. Terminating.\n", zonename)
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)
	status, buf, err := api.Post("/test", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("SendTestCommand: Error from APIpost:", err)

	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var tr music.TestResponse
	err = json.Unmarshal(buf, &tr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}
	return tr, err
}
