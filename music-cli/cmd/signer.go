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

	music "github.com/DNSSEC-Provisioning/music/common"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var signermethod, signerauth, signeraddress string

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

		err := AddSigner()
		if err != nil {
			fmt.Printf("Error from AddSigner: %v\n", err)
		}
	},
}

var updateSignerCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing signer",
	Run: func(cmd *cobra.Command, args []string) {
		if signermethod == "" {
			log.Fatalf("Error: signer method unspecified. Terminating.\n")
		}

		if signeraddress == "" {
			log.Fatalf("Error: signer address unspecified. Terminating.\n")
		}

		err := UpdateSigner()
		if err != nil {
			fmt.Printf("Error from UpdateSigner: %v\n", err)
		}
	},
}

var joinGroupCmd = &cobra.Command{
	Use:   "join",
	Short: "Join a signer to a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = SignerJoinGroup(signername, sgroupname)
	},
}

var leaveGroupCmd = &cobra.Command{
	Use:   "leave",
	Short: "Remove a signer from a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = SignerLeaveGroup(signername, sgroupname)
	},
}

var deleteSignerCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a signer from MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		err := DeleteSigner()
		if err != nil {
			fmt.Printf("Error from DeleteSigner: %v\n", err)
		}
	},
}

var listSignersCmd = &cobra.Command{
	Use:   "list",
	Short: "List all signers known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		err := ListSigners()
		if err != nil {
			fmt.Printf("Error from ListSigners: %v\n", err)
		}
	},
}

var loginSignerCmd = &cobra.Command{
	Use:   "login",
	Short: "Request that musicd login to the specified signer (not relevant for method=ddns)",
	Run: func(cmd *cobra.Command, args []string) {
		err := LoginSigner()
		if err != nil {
			fmt.Printf("Error from LoginSigner: %v\n", err)
		}
	},
}

var logoutSignerCmd = &cobra.Command{
	Use:   "logout",
	Short: "Request that musicd logout from the specified signer (not relevant for method=ddns)",
	Run: func(cmd *cobra.Command, args []string) {
		err := LogoutSigner()
		if err != nil {
			fmt.Printf("Error from LogoutSigner: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(signerCmd)
	signerCmd.AddCommand(addSignerCmd, updateSignerCmd, deleteSignerCmd, listSignersCmd, joinGroupCmd, leaveGroupCmd,
		loginSignerCmd, logoutSignerCmd)

	// promoting signername to root to make it available also for zone cmd
	signerCmd.PersistentFlags().StringVarP(&signermethod, "method", "m", "",
		"update method (ddns|desec)")
	signerCmd.PersistentFlags().StringVarP(&signerauth, "auth", "", "",
		"authdata for signer")
	signerCmd.PersistentFlags().StringVarP(&signeraddress, "address", "", "",
		"IP address of signer")
}

func AddSigner() error {

	data := music.SignerPost{
		Command: "add",
		Signer: music.Signer{
			Name:    signername,
			Method:  strings.ToLower(signermethod),
			Auth:    signerauth, // Issue #28: music.AuthDataTmp(signerauth),
			Address: signeraddress,
		},
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return nil
}

func UpdateSigner() error {
	data := music.SignerPost{
		Command: "update",
		Signer: music.Signer{
			Name:    signername,
			Method:  strings.ToLower(signermethod),
			Auth:    signerauth, // Issue #28: music.AuthDataTmp(signerauth),
			Address: signeraddress,
		},
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return nil
}

func SignerJoinGroup(signer, group string) (bool, string) {
	if signer == "" {
		log.Fatalf("SignerJoinGroup: signer not specified. Terminating.\n")
	}

	if group == "" {
		log.Fatalf("SignerJoinGroup: signer group not specified. Terminating.\n")
	}

	data := music.SignerPost{
		Command: "join",
		Signer: music.Signer{
			Name:        signer,
			Method:      strings.ToLower(signermethod),
			Auth:        signerauth, // Issue #28: music.AuthDataTmp(signerauth),
			SignerGroup: group,
		},
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return true, err.Error()
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return sr.Error, sr.ErrorMsg
}

func SignerLeaveGroup(signer, group string) (bool, string) {
	if signer == "" {
		log.Fatalf("SignerLeaveGroup: signer not specified. Terminating.\n")
	}

	if group == "" {
		log.Fatalf("SignerLeaveGroup: signer group not specified. Terminating.\n")
	}

	data := music.SignerPost{
		Command: "leave",
		Signer: music.Signer{
			Name:        signer,
			Method:      strings.ToLower(signermethod),
			Auth:        signerauth, // Issue #28: music.AuthDataTmp(signerauth),
			SignerGroup: group,
		},
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return true, err.Error()
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return sr.Error, sr.ErrorMsg
}

func DeleteSigner() error {
	data := music.SignerPost{
		Command: "delete",
		Signer: music.Signer{
			Name: signername,
		},
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return nil
}

func LoginSigner() error {
	data := music.SignerPost{
		Command: "login",
		Signer: music.Signer{
			Name: signername,
		},
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return nil
}

func LogoutSigner() error {
	data := music.SignerPost{
		Command: "logout",
		Signer: music.Signer{
			Name: signername,
		},
	}
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)

	PrintSignerResponse(err, sr.Error, sr.ErrorMsg, sr.Msg)
	return nil
}

func PrintSignerResponse(err error, iserr bool, errormsg, msg string) {
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	if iserr {
		fmt.Printf("%s\n", errormsg)
	}

	if msg != "" {
		fmt.Printf("%s\n", msg)
	}
}

func ListSigners() error {
	data := music.SignerPost{
		Command: "list",
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/signer", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from APIpost:", err)
		return err
	}
	if cliconf.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sr music.SignerResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	var out []string
	if cliconf.Verbose || showheaders {
		out = append(out, "Signer|Method|Address|SignerGroup")
	}

	for _, v := range sr.Signers {
		group := "---"
		if v.SignerGroup != "" {
			group = v.SignerGroup
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s", v.Name, v.Method, v.Address, group))
	}
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
	return nil
}
