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

// A ParentNG is a parent zone with the address of the primary and the TSIG key to use for
// updates of that zone
type ParentNG struct {
	Name     string `validate:"required"`
	Signer	 string `validate:"required"`
	Address  string // `validate:"required", "host_port"`
	TsigName string // `validate:"required"`
	TsigKey  TsigKey
	Children []string
}

type TsigKey struct {
	Name      string
	Algorithm string
	Secret    string
}

// Authoritative Nameserver
type Child struct {
	hostname string
	ip       string
	port     string
	nses     map[string]string
	cds      []*dns.CDS
	//cdnskey  []string //not implemented
	csync string
}

type ZoneNS struct {
	NSName	string
	Address	string	`validate:"host_port"`
	NSes    map[string]string
	CDS     []*dns.CDS
	//CDNSKEY  []string //not implemented
	CSYNC	string
}

type ZoneNG struct {
     Name		string
     PName		string
     DelegationNS	map[string]*ZoneNS	// map[nameserver name]*ZoneNS
     CurrentDS		[]*dns.DS
}
