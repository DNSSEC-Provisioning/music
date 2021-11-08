/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
        "bytes"
        "encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ryanuber/columnize"
	"github.com/romu42/play_go/common"
)

var sgroupname string

var signerGroupCmd = &cobra.Command{
	Use:   "signergroup",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var addSignerGroupCmd = &cobra.Command{
	Use:   "add",
	Short: "add a new signer group to MuSiC",
	Long: `A longer description that spans multiple lines and likely contains examples
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := AddSignerGroup()
		if err != nil {
		       fmt.Printf("Error from AddSignerGroup: %v\n", err)
		}
	},
}

var deleteSignerGroupCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete a signer group from MuSiC",
	Long: `A longer description that spans multiple lines and likely contains examples
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := DeleteSignerGroup()
		if err != nil {
		       fmt.Printf("Error from DeleteSignerGroup: %v\n", err)
		}
	},
}

var listSignerGroupsCmd = &cobra.Command{
	Use:   "list",
	Short: "list all signer groups known to MuSiC",
	Long: `A longer description that spans multiple lines and likely contains examples
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := ListSignerGroups()
		if err != nil {
		       fmt.Printf("Error from ListSignerGroups: %v\n", err)
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

func AddSignerGroup() error {
	apiurl := viper.GetString("musicd.baseurl") + "/signergroup"
	apikey := viper.GetString("musicd.apikey")

	data := music.SignerGroupPost{
		Command: "add",
		Name:   sgroupname,
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
		bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
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

func DeleteSignerGroup() error {
	apiurl := viper.GetString("musicd.baseurl") + "/signergroup"
	apikey := viper.GetString("musicd.apikey")

	data := music.SignerGroupPost{
		Command: "delete",
		Name:   sgroupname,
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
		bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
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
	apiurl := viper.GetString("musicd.baseurl") + "/signergroup"
	apikey := viper.GetString("musicd.apikey")

	data := music.SignerGroupPost{
		Command: "list",
		}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := music.GenericAPIpost(apiurl, apikey, "X-API-Key",
		bytebuf.Bytes(), false, cliconf.Verbose, cliconf.Debug, nil)
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
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
	if cliconf.Verbose {
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
