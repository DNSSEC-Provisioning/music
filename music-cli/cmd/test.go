/*
 *
 */
package cmd

import (
	"fmt"

	// "github.com/DNSSEC-Provisioning/music/common"

	"github.com/spf13/cobra"
)

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
	rootCmd.AddCommand(desecCmd)
	desecCmd.AddCommand(desecLoginCmd, desecLogoutCmd)
}
