package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

// Read the config file of zones to scan.
func ReadConf() map[string]*Parent {
	zones := make(map[string]*Parent)

	file, err := os.Open("zones2scan.yml")
	log.Printf("Reading %s for zones to scan\n", file.Name())
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
		// ex: catc22.se.:msat1.catch22.se.:ns1.catch22.se.:13.48.238.90:53:hmac-sha256:musiclab.parent:4ytnbnbTtA+w19eZjK6bjw/VB9SH8q/5eQKvf9BlAf8=
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
