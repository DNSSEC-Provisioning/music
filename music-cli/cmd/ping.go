/*
 *
 */
package cmd

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"

    music "github.com/DNSSEC-Provisioning/music/common"

    "github.com/spf13/cobra"
)

var pings int

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
    Use:   "ping",
    Short: "send a ping request to the musicd server, used for debugging",
    Long: `A longer description that spans multiple lines and likely contains examples
to quickly create a Cobra application.`,
    Run: func(cmd *cobra.Command, args []string) {
        PingMusicdServer()
    },
}

func init() {
    rootCmd.AddCommand(pingCmd)

    // Here you will define your flags and configuration settings.

    // Cobra supports Persistent Flags which will work for this command
    // and all subcommands, e.g.:
    // pingCmd.PersistentFlags().String("foo", "", "A help for foo")

    // Cobra supports local flags which will only run when this command
    // is called directly, e.g.:
    pingCmd.Flags().IntVarP(&pings, "count", "c", 1, "ping counter to send to server")
}

func PingMusicdServer() {

    data := music.PingPost{
        Pings: pings,
    }

    bytebuf := new(bytes.Buffer)
    json.NewEncoder(bytebuf).Encode(data)

    status, buf, err := api.Post("/ping", bytebuf.Bytes())
    if err != nil {
        log.Println("Error from Api Post:", err)
        return
    }
    if cliconf.Verbose {
        fmt.Printf("Status: %d\n", status)
    }

    var pr music.PingResponse
    err = json.Unmarshal(buf, &pr)
    if err != nil {
        log.Fatalf("Error from unmarshal: %v\n", err)
    }

    fmt.Printf("Pings: %d Pongs: %d Message: %s\n", pr.Pings, pr.Pongs, pr.Message)
    return
}
