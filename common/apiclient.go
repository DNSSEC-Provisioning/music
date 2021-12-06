/*
 * Johan Stenstam, johani@johani.org
 */
package music

// Client side API client calls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func GetAPIUrl(service, endpoint, key string, usetls, verbose bool) (string, string) {
	var protocol = "http"
	if usetls {
		protocol = "https"
	}

	ip := viper.GetString(service)
	if ip == "" {
		log.Fatalf("Service address not found in config: \"%s\". Abort.",
			service)
	}
	if verbose {
		fmt.Printf("Using service \"%s\" located at \"%s\"\n", service, ip)
	}

	// if the service string contains either https:// or http:// then that
	// will override the usetls parameter.
	if strings.HasPrefix(strings.ToLower(ip), "https://") {
		usetls = true
		protocol = "https"
		ip = ip[8:]
	} else if strings.HasPrefix(strings.ToLower(ip), "http://") {
		usetls = false
		protocol = "http"
		ip = ip[7:]
	}

	ip, port, err := net.SplitHostPort(ip)
	if err != nil {
		log.Fatalf("Error from SplitHostPort: %s. Abort.", err)
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		log.Fatalf("Illegal address specification: %s. Abort.", ip)
	}

	var pathkey string
	if strings.Contains(service, "desec") {
		pathkey = "desec.baseurl"
	} else if strings.Contains(service, "google") {
		pathkey = "google.baseurl"
	} else if strings.Contains(service, "aws") {
		pathkey = "aws.baseurl"
	} else {
		log.Fatalf("Error: unknown type of API address: %s", service)
	}

	apiurl := fmt.Sprintf("%s://%s:%s%s%s", protocol, addr.String(), port,
		viper.GetString(pathkey), endpoint)
	apikey := viper.GetString(key)
	return apiurl, apikey
}

func GenericAPIget(apiurl, apikey, authmethod string, usetls, verbose, debug bool,
	extclient *http.Client) (int, []byte, error) {

	var client *http.Client

	if extclient == nil {
		//        fmt.Fprintf(os.Stdout, "GenericAPIget Error: http client is nil.\n")
		//        return 501, nil, errors.New("http client nil")

		if usetls {
			if verbose {
				fmt.Printf("GenericAPIget: apiurl: %s (using TLS)\n", apiurl)
			}
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 1 * time.Second,
			}
		} else {
			if verbose {
				fmt.Printf("GenericAPIget: apiurl: %s\n", apiurl)
			}
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
				Timeout: 1 * time.Second,
			}
		}

	} else {
		client = extclient
	}

	var buf []byte
	if verbose {
		fmt.Println("GenericAPIget: apiurl:", apiurl)
		fmt.Println("Using API key:", apikey)
	}

	if debug {
		if usetls {
			fmt.Printf("GenericAPIget: apiurl: %s (using TLS)\n", apiurl)
		} else {
			fmt.Printf("GenericAPIget: apiurl: %s\n", apiurl)
		}
	}

	req, err := http.NewRequest("GET", apiurl, nil)
	if err != nil {
		fmt.Printf("GenericAPIget: error in http.NewRequest: %v\n", err)
	}

	if authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", apikey)
	} else if authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", apikey))
	} else if authmethod == "none" {
		// do not add any authentication header at all
	} else {
		log.Printf("Error: GenericAPIget: unknown auth method: %s. Aborting.\n",
			authmethod)
		return 501, []byte{}, errors.New(fmt.Sprintf("unknown auth method: %s", authmethod))
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Fprintf(os.Stdout, "GenericAPIget received error: %s\n", err)
		return 0, buf, err
	} else {
		buf, err = ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
	}
	// not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err
}

func GenericAPIpost(apiurl, apikey, authmethod string, data []byte,
	usetls, verbose, debug bool, extclient *http.Client) (int, []byte, error) {

	var client *http.Client

	if extclient == nil {
		if debug {
			fmt.Fprintf(os.Stdout, "GenericAPIpost: http client is nil, creating tmp client.\n")
		}

		if usetls {
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
		} else {
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
			}
		}
	} else {
		client = extclient
	}

	if usetls {
		if debug {
			fmt.Printf("GenericAPIpost: apiurl: %s (using TLS)\n", apiurl)
		}
	} else {
		if debug {
			fmt.Printf("GenericAPIpost: apiurl: %s\n", apiurl)
		}
	}

	if debug {
		fmt.Printf("GenericAPIpost: posting %d bytes of data: %v\n",
			len(data), string(data))
	}
	req, err := http.NewRequest(http.MethodPost, apiurl,
		bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")

	if authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", apikey)
	} else if authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", apikey))
	} else if authmethod == "none" {
		// do not add any authentication header at all
	} else {
		log.Printf("Error: GenericAPIpost: unknown auth method: %s. Aborting.\n", authmethod)
		return 501, []byte{}, errors.New(fmt.Sprintf("unknown auth method: %s", authmethod))
	}

	resp, err := client.Do(req)

	if err != nil {
		return 501, nil, err
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if debug {
		fmt.Printf("GenericAPIpost: response from api:\n%s\n\n", string(buf))
	}

	// not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err
}

func GenericAPIput(apiurl, apikey, authmethod string, data []byte,
	usetls, verbose, debug bool, extclient *http.Client) (int, []byte, error) {

	var client *http.Client

	if extclient == nil {
		if debug {
			fmt.Fprintf(os.Stdout, "GenericAPIput: http client is nil, creating tmp client.\n")
		}

		if usetls {
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
		} else {
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
			}
		}
	} else {
		client = extclient
	}

	if usetls {
		if debug {
			fmt.Printf("GenericAPIput: apiurl: %s (using TLS)\n", apiurl)
		}
	} else {
		if debug {
			fmt.Printf("GenericAPIput: apiurl: %s\n", apiurl)
		}
	}

	if debug {
		fmt.Printf("GenericAPIput: posting %d bytes of data: %v\n",
			len(data), string(data))
	}
	req, err := http.NewRequest(http.MethodPut, apiurl,
		bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")

	if authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", apikey)
	} else if authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", apikey))
	} else if authmethod == "none" {
		// do not add any authentication header at all
	} else {
		log.Printf("Error: GenericAPIput: unknown auth method: %s. Aborting.\n", authmethod)
		return 501, []byte{}, errors.New(fmt.Sprintf("unknown auth method: %s", authmethod))
	}

//	fmt.Printf("Faking the HTTPS PUT op. Not sending anything.\n")
//	return 301, []byte{}, nil

	resp, err := client.Do(req)

	if err != nil {
		return 501, nil, err
	}
	status := resp.StatusCode
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)

	if status == 429 {
		var de DesecError
		err = json.Unmarshal(buf, &de)
		if err != nil {
		   log.Fatalf("Error from unmarshal DesecError: %v\n", err)
		}
		// "Request was throttled. Expected available in 1 second."
		fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
		de.Detail = strings.TrimLeft(de.Detail, "Request was throttled. Expected available in ")
		fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
		de.Detail = strings.TrimRight(de.Detail, " second.")
		fmt.Printf("deSEC error detail: '%s'\n", de.Detail)
		de.Hold, err = strconv.Atoi(de.Detail)
		if err != nil {
		   log.Printf("Error from Atoi: %v\n", err)
		}
		fmt.Printf("Rate-limited. Hold period: %d\n", de.Hold)
	}

	if debug {
		fmt.Printf("GenericAPIput: response from api:\n%s\n\n", string(buf))
	}

	// not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err
}

type DesecError struct {
     Detail	string
     Hold	int
}

func GenericAPIdelete(apiurl, apikey, authmethod string, usetls, verbose, debug bool,
	extclient *http.Client) (int, []byte, error) {

	var client *http.Client
	//    var roots *x509.CertPool

	if extclient == nil {
		if debug {
			fmt.Fprintf(os.Stdout, "GenericAPIdelete: http client is nil, creating tmp client.\n")
		}

		if usetls {
			//            caCertPEM, err := ioutil.ReadFile("/etc/axfr.net/certs/axfrCA.crt")
			//            if err != nil {
			//                log.Printf("Error reading CA file: %v\n", err)
			//            }
			//
			//            roots = x509.NewCertPool()
			//            ok := roots.AppendCertsFromPEM(caCertPEM)
			//            if !ok {
			//                log.Printf("Error parsing root cert: %v\n", err)
			//            }

			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						// RootCAs: roots,
					},
				},
			}
		} else {
			client = &http.Client{
				// CheckRedirect: redirectPolicyFunc,
			}
		}
	} else {
		client = extclient
	}

	if usetls {
		if debug {
			fmt.Printf("GenericAPIdelete: apiurl: %s (using TLS)\n", apiurl)
		}
	} else {
		if debug {
			fmt.Printf("GenericAPIdelete: apiurl: %s\n", apiurl)
		}
	}

	req, err := http.NewRequest(http.MethodDelete, apiurl, nil)

	if authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", apikey)
	} else if authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", apikey))
	} else if authmethod == "none" {
		// do not add any authentication header at all
	} else {
		log.Printf("Error: GenericAPIdelete: unknown auth method: %s. Aborting.\n", authmethod)
		return 501, []byte{}, errors.New(fmt.Sprintf("unknown auth method: %s", authmethod))
	}

	resp, err := client.Do(req)

	if err != nil {
		// handle error
		fmt.Fprintf(os.Stdout, "GenericAPIdelete blew up. Error: %s\n", err)
		os.Exit(1)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if debug {
		log.Println("GenericAPIdelete: response from api:", string(buf))
	}

	defer resp.Body.Close()
	// not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err
}

// api client
func NewClient(verbose, debug bool) *Api {
	api := Api{}

	api.Apiurl = viper.GetString("musicd.baseurl")
	api.apiKey = viper.GetString("musicd.apikey")
	api.Authmethod = viper.GetString("musicd.authmethod")

	rootCAPool := x509.NewCertPool()
	rootCA, err := ioutil.ReadFile(viper.GetString("musicd.rootCApem"))

	if err != nil {
		log.Fatalf("reading cert failed : %v", err)
	}

	rootCAPool.AppendCertsFromPEM(rootCA)

	api.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAPool,
			},
		},
	}
	// api.Client = &http.Client{}
	api.Debug = debug
	api.Verbose = verbose
	// log.Printf("client is a: %T\n", api.Client)

	if debug {
		fmt.Printf("apiurl is: %s \napikey is: %s \nauthmethod is: %s \n", api.Apiurl, api.apiKey, api.Authmethod)
	}

	return &api
}

// request helper function
func (api *Api) requestHelper(req *http.Request) (int, []byte, error) {

	req.Header.Add("Content-Type", "application/json")

	if api.Authmethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.apiKey)
	} else if api.Authmethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.apiKey))
	} else if api.Authmethod == "" {
		// do not add any authentication header at all
	} else {
		log.Printf("Error: Client API Post: unknown auth method: %s. Aborting.\n", api.Authmethod)
		return 501, []byte{}, fmt.Errorf("unknown auth method: %s", api.Authmethod)
	}

	resp, err := api.Client.Do(req)

	if err != nil {
		return 501, nil, err
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)

	if api.Debug {
		fmt.Printf("requestHelper: received %d bytes of response data: %v\n",
			len(buf), string(buf))
	}

	//not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err

}

// api Post
func (api *Api) Post(endpoint string, data []byte) (int, []byte, error) {

	if api.Debug {
		fmt.Printf("api.Post: posting %d bytes of data: %v\n",
			len(data), string(data))
	}

	req, err := http.NewRequest(http.MethodPost, api.Apiurl+endpoint, bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Delete
// not tested
func (api *Api) Delete(endpoint string, data []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodDelete, api.Apiurl, nil)
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Get
// not tested
func (api *Api) Get(endpoint string) (int, []byte, error) {

	req, err := http.NewRequest(http.MethodGet, api.Apiurl+endpoint, nil)
	if err != nil {
		log.Fatalf("Error from http.NewRequest: Error: %v", err)
	}
	return api.requestHelper(req)
}

// api Put
// coming soon to a code base nere you.
