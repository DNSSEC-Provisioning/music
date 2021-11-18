/*
 *
 */
package cmd

import (
	"fmt"
	"os"

	"github.com/DNSSEC-Provisioning/music/common"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

const timefmt = "2006-01-02 15:04:05"

// zoneCmd represents the zone command
var desecZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Manipulate zones stored in the deSEC service via their API",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("zone called")
	},
}

// zoneAddCmd represents the zone command
var desecZoneAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a zone to be served by deSEC (note that the zone will be initially empty)",
	Run: func(cmd *cobra.Command, args []string) {
		if zonename == "" {
			fmt.Printf("Cannot add a zone without a name. Use '-z'\n")
			os.Exit(1)
		}
		music.DesecAddZone(&cliconf, zonename, tokvip)
	},
}

// zoneAddCmd represents the zone command
var desecZoneDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a zone from the deSEC service",
	Run: func(cmd *cobra.Command, args []string) {
		if zonename == "" {
			fmt.Printf("Cannot delete a zone without a name. Use '-z'\n")
			os.Exit(1)
		}
		music.DesecDeleteZone(&cliconf, zonename, tokvip)
	},
}

// zoneListCmd represents the zone command
var desecZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List one or all zones served by deSEC",
	Run: func(cmd *cobra.Command, args []string) {
		zl, _ := music.DesecListZone(&cliconf, zonename, tokvip)

		if len(zl) > 0 {
			var out = []string{"Zone|Created|Published"}
			for _, v := range zl {
				out = append(out, fmt.Sprintf("%s|%s|%s", v.Name,
					v.Created.Format(timefmt),
					v.Published.Format(timefmt)))
			}
			fmt.Printf(columnize.SimpleFormat(out))
			fmt.Println()
		}
	},
}

func init() {
	desecCmd.AddCommand(desecZoneCmd)
	desecZoneCmd.AddCommand(desecZoneAddCmd, desecZoneDeleteCmd, desecZoneListCmd)
}
