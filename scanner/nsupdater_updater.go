package main

// Code from: https://github.com/DNSSEC-Provisioning/multi-signer-controller/
import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

type Updater interface {
	//Update(fqdn, signer string, inserts, removes *[][]dns.RR, output *[]string) error
	Update(fqdn string, parent *Parent, inserts, removes *[][]dns.RR, output *[]string) error
	RemoveRRset(fqdn, signer string, rrsets [][]dns.RR, output *[]string) error
}

var Updaters map[string]Updater = make(map[string]Updater)

func GetUpdater(type_ string) Updater {
	updater, ok := Updaters[type_]
	if !ok {
		log.Fatal("No updater type", type_)
	}
	return updater
}

type NsupdateUpdater struct {
}

func init() {
	Updaters["nsupdate"] = &NsupdateUpdater{}
}

//func (n *NsupdateUpdater) Update(fqdn, signer string, inserts, removes *[][]dns.RR, output *[]string) error {
func (n *NsupdateUpdater) Update(fqdn string, parent *Parent, inserts, removes *[][]dns.RR, output *[]string) error {
	inserts_len := 0
	removes_len := 0
	if inserts != nil {
		for _, insert := range *inserts {
			inserts_len += len(insert)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			removes_len += len(remove)
		}
	}
	if inserts_len == 0 && removes_len == 0 {
		return fmt.Errorf("Inserts and removes empty, nothing to do")
	}

	ip := parent.ip + ":" + parent.port
	if ip == "" {
		return fmt.Errorf("No ip|host for signer %s", parent.hostname)
	}

	tsigkey := parent.keyname
	if tsigkey == "" {
		return fmt.Errorf("Missing signer %s TSIG key %s", parent.hostname, tsigkey)
	}

	secret := parent.secret
	if secret == "" {
		return fmt.Errorf("Missing TSIG key secret for %s", tsigkey)
	}

	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	log.Printf("%s\n", fqdn)
	if inserts != nil {
		for _, insert := range *inserts {
			m.Insert(insert)
			log.Printf(" nsupdater inserts - %v\n", m)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			log.Printf(" nsupdater removes - %v\n", remove)
			m.Remove(remove)
			log.Printf(" nsupdater removes - %v\n", m)
		}
	}
	m.SetTsig(tsigkey, dns.HmacSHA256, 300, time.Now().Unix())

	*output = append(*output, fmt.Sprintf("nsupdate: Sending inserts %d, removals %d to signer %s", inserts_len, removes_len, parent.hostname))

	c := new(dns.Client)
	//c.TsigSecret = map[string]string{tsigkey + ".": secret}
	c.TsigSecret = map[string]string{tsigkey: secret}
	log.Printf("nsupdater: secret is %v\n", c.TsigSecret)
	in, rtt, err := c.Exchange(m, ip)
	if err != nil {
		return err
	}

	*output = append(*output, fmt.Sprintf("nsupdate: Update took %v, rcode %s", rtt, dns.RcodeToString[in.MsgHdr.Rcode]))

	return nil
}

func (d *NsupdateUpdater) RemoveRRset(fqdn, signer string, rrsets [][]dns.RR, output *[]string) error {
	rrsets_len := 0
	for _, rrset := range rrsets {
		rrsets_len += len(rrset)
	}
	if rrsets_len == 0 {
		return fmt.Errorf("rrset(s) is empty, nothing to do")
	}

	ip := "13.48.238.90"
	if ip == "" {
		return fmt.Errorf("No ip|host for signer %s", signer)
	}

	tsigkey := "musiclab.parent"
	if tsigkey == "" {
		return fmt.Errorf("Missing signer %s TSIG key %s", signer, tsigkey)
	}

	secret := "KChJOq1qPJ9mHK5TRDPL9FuVwh4RoWPrTrBKpi1iLrI="
	if secret == "" {
		return fmt.Errorf("Missing TSIG key secret for %s", tsigkey)
	}

	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	for _, rrset := range rrsets {
		m.RemoveRRset(rrset)
	}
	m.SetTsig(tsigkey+".", dns.HmacSHA256, 300, time.Now().Unix())

	*output = append(*output, fmt.Sprintf("nsupdate: Sending remove rrset(s) %d to signer %s", rrsets_len, signer))

	c := new(dns.Client)
	c.TsigSecret = map[string]string{tsigkey + ".": secret}
	in, rtt, err := c.Exchange(m, ip)
	if err != nil {
		return err
	}

	*output = append(*output, fmt.Sprintf("nsupdate: Update took %v, rcode %s", rtt, dns.RcodeToString[in.MsgHdr.Rcode]))

	return nil
}
