package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

func GetIP(hostname string, server string, port string) string {
	log.Printf("Getting %s IP from %s\n", hostname, server)
	m := new(dns.Msg)
	m.SetQuestion(hostname, dns.TypeA)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		log.Printf("%s: Unable to fetch ip from %s: %s", hostname, server, err)
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("No IP Received, maybe out of bailiwick Rcode: %v\n", dns.RcodeToString[r.Rcode])
		ip := ""
		return ip
	} else {
		// Only grabbing the first RR
		answer := r.Answer[0].String()
		ip := answer[strings.LastIndex(answer, "\t")+1:]
		// debug	fmt.Println(ip)
		return ip
	}
}

func GetNS(zone string, hostname, server string, port string) []string {
	log.Printf("Getting %s NSes from %s %s\n", zone, hostname, server)
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		log.Printf("%s: Unable to fetch NSes from %s: %s", zone, server, err)
	}

	var nses []string
	if r.MsgHdr.Authoritative {
		for _, a := range r.Answer {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}
			nses = append(nses, ns.String()[strings.LastIndex(ns.String(), "\t")+1:])
		}
	} else {

		for _, a := range r.Ns {
			ns, ok := a.(*dns.NS)
			if !ok {
				continue
			}
			nses = append(nses, ns.String()[strings.LastIndex(ns.String(), "\t")+1:])
		}
	}
	return nses
}

//func GetDS(zone string, hostname string, server string, port string) []string {
func GetDS(zone string, hostname string, server string, port string) []*dns.DS {
	log.Printf("Getting %s DSes from %s %s\n", zone, hostname, server)
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		log.Printf("%s: Unable to fetch DSes from %s: %s", zone, server, err)
	}

	//var dses []string
	var dses []*dns.DS
	for _, a := range r.Answer {
		ds, ok := a.(*dns.DS)
		if !ok {
			continue
		}
		//dses = append(dses, ds.String()[strings.LastIndex(ds.String(), "\t")+1:])
		// I may actually want the entire record for later use.
		//	dses = append(dses, ds.String())
		dses = append(dses, ds)
	}
	log.Printf("DS Slice: %v", dses)
	return dses
}

//func GetCDS(zone string, hostname string, server string, port string) []string {
func GetCDS(zone string, hostname string, server string, port string) []*dns.CDS {
	log.Printf("Getting %s CDSes from %s %s\n", zone, hostname, server)
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeCDS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		log.Printf("%s: Unable to fetch CDSes from %s: %s", zone, server, err)
	}

	//var cdses []string
	var cdses []*dns.CDS
	for _, a := range r.Answer {
		cds, ok := a.(*dns.CDS)
		if !ok {
			continue
		}
		//cdses = append(cdses, cds.String()[strings.LastIndex(cds.String(), "\t")+1:])
		// I may actually want the entire record for later use.
		//cdses = append(cdses, cds.String())
		cdses = append(cdses, cds)
	}
	log.Printf("CDS Slice: %v", cdses)
	return cdses
}

func GetCsync(zone string, hostname string, server string, port string) string {
	log.Printf("Getting %s Csync from %s %s\n", zone, hostname, server)
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeCSYNC)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		log.Printf("%s: Unable to fetch CSYNC from %s: %s", zone, server, err)
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf("No CSYNC Received: %v\n", dns.RcodeToString[r.Rcode])
		csync := ""
		return csync
	} else if len(r.Answer) == 0 {
		log.Printf("No CSYNC RR\n")
		csync := ""
		return csync
	} else {
		// Only grabbing the first RR
		answer := r.Answer[0].String()
		csync := answer[strings.LastIndex(answer, "\t")+1:]
		// debug	fmt.Println(ip)
		return csync
	}
}

//func CreateNsUpdate(zone string, parent *Parent) ([]*dns.NS, []*dns.NS) {
func CreateNsUpdate(zone string, parent *Parent) ([]dns.RR, []dns.RR, error) {
	// This logic needs discussion, I am shooting from the hip here
	cNsesmap := make(map[string]string)
	pNsesmap := make(map[string]string)
	//var nsAdd []string
	var nsAdd []dns.RR
	//var nsRemove []string
	var nsRemove []dns.RR

	// Get a full map of "all" nses the children know about for comparison
	for pkey, child := range parent.child_ns {
		pNsesmap[pkey] = pkey
		for ckey, cvalue := range child.nses {
			cNsesmap[ckey] = cvalue
		}
	}

	// Compare NS for all children
	// If not match at children report
	for _, child := range parent.child_ns {
		for ckey, _ := range cNsesmap {
			if _, ok := child.nses[ckey]; !ok {
				return nil, nil, fmt.Errorf("children are not in sync send error, ns:%s is not in child:%s", ckey, child.hostname)
			}
		}
	}

	// Diff from parent
	// If in child.nses not in parent.child_nses = add to parent
	for key, _ := range cNsesmap {
		if _, ok := pNsesmap[key]; !ok {
			addme, err := dns.NewRR(fmt.Sprintf("%s 30 IN NS %s", zone, key))
			if err != nil {
				log.Printf("error: %v\n", err)
			}
			nsAdd = append(nsAdd, addme)
		}
	}

	// If in parent.child_nses not in child = remove from parent
	for key, _ := range pNsesmap {
		if _, ok := cNsesmap[key]; !ok {
			addme, err := dns.NewRR(fmt.Sprintf("%s 30 IN NS %s", zone, key))
			if err != nil {
				log.Printf("error: %v\n", err)
			}
			nsRemove = append(nsRemove, addme)
		}
	}

	log.Printf("%T adds  -> %v", nsAdd, nsAdd)
	log.Printf("%T removes  -> %v", nsRemove, nsRemove)
	return nsAdd, nsRemove, nil
}

func CreateDsUpdate(zone string, parent *Parent) ([]*dns.CDS, []*dns.DS) {
	dsmap := make(map[string]*dns.DS)
	cdsmap := make(map[string]*dns.CDS)
	var dsremove []*dns.DS
	var dsadd []*dns.CDS // Gets converte to DS in main.go
	log.Printf("DS update Code starts here\n")

	// DSes
	for _, ds := range parent.ds {
		dsmap[fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm,
			ds.DigestType, ds.Digest)] = ds
	}
	log.Printf("%s -> DS = %v", parent.hostname, dsmap)

	// CDSes TODO: Possible bug that the childrens CDS records are not compared to each other.
	for _, child := range parent.child_ns {
		for _, cds := range child.cds {
			cdsmap[fmt.Sprintf("%d %d %d %s", cds.KeyTag, cds.Algorithm,
				cds.DigestType, cds.Digest)] = cds
		}
		log.Printf("%s -> CDS = %v", child.hostname, cdsmap)
	}

	// if in CDSmap but not in DSmap = add to DS-SET
	for key, _ := range cdsmap {
		if _, ok := dsmap[key]; !ok {
			dsadd = append(dsadd, cdsmap[key])
		}
	}

	// if in DSmap but not in CDSmap = Remove from DS-SET
	for key, _ := range dsmap {
		if _, ok := cdsmap[key]; !ok {
			dsremove = append(dsremove, dsmap[key])
		}
	}

	log.Printf("Add to DS set %v", dsadd)
	log.Printf("Remove from DS set %v", dsremove)
	return dsadd, dsremove
}

/*
Not Implemented:
func GetCdnskey()
*/
