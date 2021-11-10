package music

import (
    "fmt"
    "strings"
    "time"

    "github.com/miekg/dns"
)

type DdnsUpdater struct {
}

func init() {
    Updaters["ddns"] = &DdnsUpdater{}
}

func (u *DdnsUpdater) Update(signer *Signer, fqdn string, inserts, removes *[][]dns.RR) error {
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
    in, _, err := c.Exchange(m, signer.Address+":53") // TODO: add DnsAddress or solve this in a better way
    if err != nil {
        return err
    }
    if in.MsgHdr.Rcode != dns.RcodeSuccess {
        return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
    }

    return nil
}

func (u *DdnsUpdater) RemoveRRset(signer *Signer, fqdn string, rrsets [][]dns.RR) error {
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
    in, _, err := c.Exchange(m, signer.Address)
    if err != nil {
        return err
    }
    if in.MsgHdr.Rcode != dns.RcodeSuccess {
        return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
    }

    return nil
}
