package music

import (
    "fmt"
    // "time"

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

    // TODO: need TSIG key + secret from signer.Auth

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
    // TOOD: once we have TSIG
    // m.SetTsig(tsigkey+".", dns.HmacSHA256, 300, time.Now().Unix())

    c := new(dns.Client)
    // TOOD: once we have TSIG
    // c.TsigSecret = map[string]string{tsigkey + ".": secret}
    // TODO: in, rtt - use?
    _, _, err := c.Exchange(m, signer.Address)
    if err != nil {
        return err
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

    // TODO: need TSIG key + secret from signer.Auth

    m := new(dns.Msg)
    m.SetUpdate(fqdn)
    for _, rrset := range rrsets {
        m.RemoveRRset(rrset)
    }
    // TOOD: once we have TSIG
    // m.SetTsig(tsigkey+".", dns.HmacSHA256, 300, time.Now().Unix())

    c := new(dns.Client)
    // TOOD: once we have TSIG
    // c.TsigSecret = map[string]string{tsigkey + ".": secret}
    // TODO: in, rtt - use?
    _, _, err := c.Exchange(m, signer.Address)
    if err != nil {
        return err
    }

    return nil
}
