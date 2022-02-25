package main

import "github.com/miekg/dns"

// Parent Server info and child info according to Parent
type Parent struct {
	pzone    string
	hostname string
	ip       string
	port     string
	hmac     string
	keyname  string
	secret   string
	child_ns map[string]*Child
	ds       []*dns.DS
}

// Authoritave Nameserver
type Child struct {
	hostname string
	ip       string
	port     string
	nses     map[string]string
	cds      []*dns.CDS
	//cdnskey  []string //not implemented
	csync string
}
