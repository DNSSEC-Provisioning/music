package main

// Code from: https://github.com/DNSSEC-Provisioning/multi-signer-controller/
import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

type UpdaterNG interface {
     //Update(fqdn, signer string, inserts, removes *[][]dns.RR, output *[]string) error
	Update(fqdn string, parent ParentNG, inserts, removes *[][]dns.RR, output *[]string) error
	RemoveRRset(fqdn, signer string, rrsets [][]dns.RR, output *[]string) error
}

var UpdatersNG map[string]UpdaterNG = make(map[string]UpdaterNG)

func GetUpdaterNG(type_ string) UpdaterNG {
	updaterng, ok := UpdatersNG[type_]
	if !ok {
		log.Fatal("No updaterNG type", type_)
	}
	return updaterng
}

type ParentUpdaterNG struct {
}

func init() {
	UpdatersNG["parent"] = &ParentUpdaterNG{}
}

func (n *ParentUpdaterNG) Update(fqdn string, parent ParentNG, inserts,
     			  removes *[][]dns.RR, output *[]string) error {
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

	if parent.Address == "" {
		return fmt.Errorf("No address for parent %s", parent.Name)
	}

	if parent.TsigName == "" {
		return fmt.Errorf("Missing parent %s TSIG key", parent.Name)
	}

	if parent.TsigKey.Secret == "" {
		return fmt.Errorf("Missing TSIG key secret for TSIG key %s",
		       parent.TsigName)
	}

	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	log.Printf("%s\n", fqdn)
	if inserts != nil {
		for _, insert := range *inserts {
			m.Insert(insert)
			log.Printf(" parentNG inserts - %v\n", m)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			log.Printf(" parentNG removes - %v\n", remove)
			m.Remove(remove)
			log.Printf(" parentNG removes - %v\n", m)
		}
	}
	m.SetTsig(parent.TsigName, dns.HmacSHA256, 300, time.Now().Unix())

	*output = append(*output, fmt.Sprintf("parentNG: Sending inserts %d, removals %d to signer %s", inserts_len, removes_len, parent.Name))	// should be a servername?

	c := new(dns.Client)
	//c.TsigSecret = map[string]string{tsigkey + ".": secret}
	c.TsigSecret = map[string]string{parent.TsigName: parent.TsigKey.Secret}
	log.Printf("parentupdater: secret is %v\n", c.TsigSecret)
	in, rtt, err := c.Exchange(m, parent.Address)
	if err != nil {
		return err
	}

	*output = append(*output, fmt.Sprintf("nsupdate: Update took %v, rcode %s", rtt, dns.RcodeToString[in.MsgHdr.Rcode]))

	return nil
}

func (d *ParentUpdaterNG) RemoveRRset(fqdn, signer string, rrsets [][]dns.RR, output *[]string) error {
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
