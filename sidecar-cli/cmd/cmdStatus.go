/*
* Rog Murray, roger.murray@internetstiftelsen.se
 */
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.AddCommand(statusZonesCmd)
	statusCmd.AddCommand(statusSignerCmd)
	statusCmd.AddCommand(statusSignerGroupCmd)
	statusCmd.AddCommand(statusAllCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current status of MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var statusZonesCmd = &cobra.Command{
	Use:   "zone",
	Short: "Show current status of all zones in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		ZoneStatus()
	},
}

var statusSignerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Show current status of all signers in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		SignerStatus()
	},
}

var statusSignerGroupCmd = &cobra.Command{
	Use:   "signergroup",
	Short: "Show current status of all signergroups in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		SignerGroupStatus()
	},
}

var statusAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Show current status of MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		fmt.Println("-------------------   -------------------")
		ZoneStatus()
		fmt.Println("-------------------   -------------------")
		SignerStatus()
		fmt.Println("-------------------   -------------------")
		SignerGroupStatus()
		fmt.Println("-------------------   -------------------")
	},
}
