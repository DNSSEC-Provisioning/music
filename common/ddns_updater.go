package music

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DdnsUpdater struct {
}

func init() {
	Updaters["ddns"] = &DdnsUpdater{}
}

func (u *DdnsUpdater) SetChannels(fetch, update chan SignerOp) {
	// no-op
}

func (u *DdnsUpdater) SetApi(api Api) {
	// no-op
}

func (u *DdnsUpdater) GetApi() Api {
	// no-op
	return Api{}
}

func (u *DdnsUpdater) Update(signer *Signer, zone, fqdn string,
	inserts, removes *[][]dns.RR) error {
	// log.Printf("DDNS Updater: signer: %s, fqdn: %s inserts: %v removes: %v\n",
	// 	signer.Name, fqdn, inserts, removes)
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
	log.Printf("DDNS Updater: signer: %s, fqdn: %s inserts: %d removes: %d\n",
		signer.Name, fqdn, inserts_len, removes_len)
	if inserts_len == 0 && removes_len == 0 {
		return fmt.Errorf("Inserts and removes empty, nothing to do")
	}

	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name)
	}
	if signer.Auth == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name)
	}
	tsig := strings.SplitN(signer.Auth, ":", 2)
	if len(tsig) != 2 {
		return fmt.Errorf("Incorrect TSIG for signer %s", signer.Name)
	}

	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	if inserts != nil {
		for _, insert := range *inserts {
			m.Insert(insert)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			m.Remove(remove)
		}
	}
	m.SetTsig(tsig[0]+".", dns.HmacSHA256, 300, time.Now().Unix())

	c := new(dns.Client)
	c.TsigSecret = map[string]string{tsig[0] + ".": tsig[1]}
	in, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		return err
	}
	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	return nil
}

func (u *DdnsUpdater) RemoveRRset(signer *Signer, zone, fqdn string, rrsets [][]dns.RR) error {
	rrsets_len := 0
	for _, rrset := range rrsets {
		rrsets_len += len(rrset)
	}
	if rrsets_len == 0 {
		return fmt.Errorf("rrset(s) is empty, nothing to do")
	}

	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name)
	}
	if signer.Auth == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name)
	}
	tsig := strings.SplitN(signer.Auth, ":", 2)
	if len(tsig) != 2 {
		return fmt.Errorf("Incorrect TSIG for signer %s", signer.Name)
	}

	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	for _, rrset := range rrsets {
		m.RemoveRRset(rrset)
	}
	m.SetTsig(tsig[0]+".", dns.HmacSHA256, 300, time.Now().Unix())

	c := new(dns.Client)
	c.TsigSecret = map[string]string{tsig[0] + ".": tsig[1]}
	in, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		return err
	}
	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	return nil
}

func (u *DdnsUpdater) FetchRRset(signer *Signer, zone, fqdn string,
	rrtype uint16) (error, []dns.RR) {
	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name), []dns.RR{}
	}
	if signer.Auth == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name), []dns.RR{}
	}
	tsig := strings.SplitN(signer.Auth, ":", 2)
	if len(tsig) != 2 {
		return fmt.Errorf("Incorrect TSIG for signer %s", signer.Name), []dns.RR{}
	}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, rrtype)
	// m.SetEdns0(4096, true)
	m.SetTsig(tsig[0]+".", dns.HmacSHA256, 300, time.Now().Unix())

	// c := new(dns.Client)
	c := dns.Client{Net: "tcp"}
	c.TsigSecret = map[string]string{tsig[0] + ".": tsig[1]}
	r, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		return err, []dns.RR{}
	}

	if r.MsgHdr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Fetch of %s RRset failed, RCODE = %s", dns.TypeToString[rrtype], dns.RcodeToString[r.MsgHdr.Rcode]), []dns.RR{}
	}

	log.Printf("Length of %s answer from %s: %d RRs\n",
		dns.TypeToString[rrtype],
		signer.Name+":"+signer.Port, len(r.Answer))

	var rrs []dns.RR

	// XXX: Here we want to filter out all RRs that are of other types than the
	//      rrtype we're looking for. It would be much better to have a general
	//      check for a.(type) == rrtype, but I have not figured out how.

	for _, a := range r.Answer {
		switch dns.TypeToString[rrtype] {

		case "DNSKEY":
			rr, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CDS":
			rr, ok := a.(*dns.CDS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CDNSKEY":
			rr, ok := a.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "NS":
			rr, ok := a.(*dns.NS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "DS":
			rr, ok := a.(*dns.DS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "SOA":
			rr, ok := a.(*dns.SOA)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CSYNC":
			rr, ok := a.(*dns.CSYNC)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		}
	}

	return nil, rrs
}
