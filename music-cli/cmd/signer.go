/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/DNSSEC-Provisioning/music/music"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var signermethod, signerauth, signeraddress, signerport string
var signernotcp, signernotsig bool

// signerCmd represents the signer command
var signerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Signer commands",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var addSignerCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new signer to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		if signermethod == "" {
			log.Fatalf("Error: signer method unspecified. Terminating.\n")
		}

		if signeraddress == "" {
			log.Fatalf("Error: signer address unspecified. Terminating.\n")
		}

		var authdata music.AuthData
		if signerauth != "" {
			authdata = music.ParseSignerAuth(signerauth, signermethod)
		}

		//		if signerport == "" {
		//			signerport = "53"
		//		}
		sr := SendSignerCmd(music.SignerPost{
			Command: "add",
			Signer: music.Signer{
				Name:   signername,
				Method: strings.ToLower(signermethod),
				// Auth:    signerauth, // Issue #28: music.AuthDataTmp(signerauth),
				Auth:    authdata,
				Address: signeraddress,
				Port:    signerport, // set to 53 if not specified
				UseTcp:  !signernotcp,
				UseTSIG: !signernotsig,
			},
			SignerGroup: sgroupname, // may be unspecified
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

// XXX: Note that this new version of signer update will just send parameters that are specified
//      without checking if they are or not. So the reciever end (api server) must do the checking.
var updateSignerCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing signer",
	Run: func(cmd *cobra.Command, args []string) {
		if signername == "" {
			log.Fatalf("Error: signer to update not specified. Terminating.\n")
		}

		var authdata music.AuthData
		if signerauth != "" {
			authdata = music.ParseSignerAuth(signerauth, signermethod)
		}

		sr := SendSignerCmd(music.SignerPost{
			Command: "update",
			Signer: music.Signer{
				Name:    signername,
				Address: signeraddress,
				Method:  strings.ToLower(signermethod),
				// Auth:    signerauth, // Issue #28: music.AuthDataTmp(signerauth),
				Auth:    authdata,
				Port:    signerport, // set to 53 if not specified
				UseTcp:  !signernotcp,
				UseTSIG: !signernotsig,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

var joinGroupCmd = &cobra.Command{
	Use:   "join",
	Short: "Join a signer to a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		if signername == "" {
			log.Fatalf("SignerJoinGroup: signer not specified. Terminating.\n")
		}

		if sgroupname == "" {
			log.Fatalf("SignerJoinGroup: signer group not specified. Terminating.\n")
		}

		sr := SendSignerCmd(music.SignerPost{
			Command: "join",
			Signer: music.Signer{
				Name:        signername,
				SignerGroup: sgroupname,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

var leaveGroupCmd = &cobra.Command{
	Use:   "leave",
	Short: "Remove a signer from a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		if signername == "" {
			log.Fatalf("SignerLeaveGroup: signer not specified. Terminating.\n")
		}

		if sgroupname == "" {
			log.Fatalf("SignerLeaveGroup: signer group not specified. Terminating.\n")
		}

		sr := SendSignerCmd(music.SignerPost{
			Command: "leave",
			Signer: music.Signer{
				Name:        signername,
				SignerGroup: sgroupname,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

var deleteSignerCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a signer from MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		sr := SendSignerCmd(music.SignerPost{
			Command: "delete",
			Signer: music.Signer{
				Name: signername,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

var listSignersCmd = &cobra.Command{
	Use:   "list",
	Short: "List all signers known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {

		sr := SendSignerCmd(music.SignerPost{
			Command: "list",
		})
		PrintSigners(sr)
	},
}

var loginSignerCmd = &cobra.Command{
	Use:   "login",
	Short: "Request that musicd login to the specified signer (not relevant for method=ddns)",
	Run: func(cmd *cobra.Command, args []string) {
		sr := SendSignerCmd(music.SignerPost{
			Command: "login",
			Signer: music.Signer{
				Name: signername,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

var logoutSignerCmd = &cobra.Command{
	Use:   "logout",
	Short: "Request that musicd logout from the specified signer (not relevant for method=ddns)",
	Run: func(cmd *cobra.Command, args []string) {
		sr := SendSignerCmd(music.SignerPost{
			Command: "logout",
			Signer: music.Signer{
				Name: signername,
			},
		})
		PrintSignerResponse(sr.Error, sr.ErrorMsg, sr.Msg)
	},
}

func init() {
	rootCmd.AddCommand(signerCmd)
	signerCmd.AddCommand(addSignerCmd, updateSignerCmd, deleteSignerCmd, listSignersCmd,
		joinGroupCmd, leaveGroupCmd, loginSignerCmd, logoutSignerCmd)

	signerCmd.PersistentFlags().StringVarP(&signermethod, "method", "m", "",
		"update method (ddns|desec)")
	signerCmd.PersistentFlags().StringVarP(&signerauth, "auth", "", "",
		fmt.Sprintf("authdata for signer:\nDDNS: algname:key.name:secret\ndeSEC: ?"))
	signerCmd.PersistentFlags().StringVarP(&signeraddress, "address", "", "",
		"IP address of signer")
	signerCmd.PersistentFlags().StringVarP(&signerport, "port", "p", "53",
		"Port of signer")
	signerCmd.PersistentFlags().BoolVarP(&signernotcp, "notcp", "", false, "Don't use TCP (use UDP), debug")
	signerCmd.PersistentFlags().BoolVarP(&signernotsig, "notsig", "", false, "Don't use TSIG, debug")
}

func SendSignerCmd(data music.SignerPost) music.SignerResponse {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("Error from api.Post: %v", err)
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("SendSignerCmd: Error from json.Unmarshal: %v", err)
	}

	return sr
}

func PrintSignerResponse(iserr bool, errormsg, msg string) {
	if iserr {
		fmt.Printf("%s\n", errormsg)
	}

	if msg != "" {
		fmt.Printf("%s\n", msg)
	}
}

func PrintSigners(sr music.SignerResponse) {
	if len(sr.Signers) != 0 {
		var out []string
		if cliconf.Verbose || showheaders {
			out = append(out, "Signer|Method|Address|Port|SignerGroups")
		}

		for _, v := range sr.Signers {
			groups := []string{"---"}
			if len(v.SignerGroups) != 0 {
				groups = v.SignerGroups
			}
			gs := strings.Join(groups, ", ")
			out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s", v.Name, v.Method,
				v.Address, v.Port, gs))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}
