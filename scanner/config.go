package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type Config struct {
        Scanner	   ScannerConf
	Parents	   []ParentConf
	ParentMap  map[string]ParentConf
	Keys	   []TsigKey
	KeyMap	   map[string]TsigKey
	Log	   LogConf
}

type ScannerConf struct {
        Zones	 string	`validate:"required", "file"`
	Interval int
}

type ParentConf struct {
     	Name	   string
	TsigName   string
	TsigKey	   TsigKey
	Children   []string
}

type TsigKey struct {
        Name 	    string
     	Algorithm   string
	Secret	    string
}

type LogConf struct {
	Level	string	`validate:"required"`
}

// Read the config file of zones to scan.
func ReadConf(filename string) map[string]*Parent {
	zones := make(map[string]*Parent)

	if filename == "" {
		log.Fatalf("File with zones to scan not specified")
	}

	file, err := os.Open(filename)
	log.Printf("Reading %s for zones to scan\n", filename)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "#") {
			continue
		}

		// For each line in the list create Zone Parent struct
		// parent:child:child_ns:ns_addr:ns_port:algorithm:keyname:secret

		// ex: catch22.se.:msat1.catch22.se.:ns1.catch22.se.:13.48.238.90:53:hmac-sha256:musiclab.parent:4ytnbnbTtA+w19eZjK6bjw/VB9SH8q/5eQKvf9BlAf8=
		parts := strings.Split(line, ":")
		z := &Parent{
			pzone:    parts[0],
			hostname: parts[2],
			ip:       parts[3],
			port:     parts[4],
			hmac:     parts[5],
			keyname:  parts[6],
			secret:   parts[7],
		}
		zones[parts[1]] = z
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return zones
}

// Read the config file of zones to scan.
func ReadConfNG(conf *Config) map[string]*Parent {
	zones := make(map[string]*Parent)
	km := map[string]TsigKey{}
	pm := map[string]ParentConf{}

	err := viper.Unmarshal(&conf)
	if err != nil {
	   log.Fatalf("viper: Unable to decode into struct: %v", err)
	}

	fmt.Printf("Keys (%d): %v\n", len(conf.Keys), conf.Keys)
	for _, k := range conf.Keys {
	    k.Name = dns.Fqdn(k.Name)
	    km[k.Name] = k
	}
	
	var ok bool
	fmt.Printf("There are %d parent zones:\n", len(conf.Parents))
	for _, p := range conf.Parents {
	    p.Name = dns.Fqdn(p.Name)
	    p.TsigName = dns.Fqdn(p.TsigName)
	    if p.TsigKey, ok = km[p.TsigName]; !ok {
	       log.Fatalf("TSIG key '%s' is unknown.", p.TsigName)
	    }
	    pm[p.Name] = p
	    fmt.Printf("%s (%d children): %v\n", dns.Fqdn(p.Name), len(p.Children), p.Children)
	    for _, c := range p.Children {
	    	c = dns.Fqdn(c)
	    	if !strings.HasSuffix(c, p.Name) {
		   log.Fatalf("Error: %s is not a child of %s", c, p.Name)
		}
		zones[c] = &Parent{
				pzone:	p.Name,
			   }
	    }
	}

	return zones
}
