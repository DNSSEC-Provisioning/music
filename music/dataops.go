/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	// "errors"
	"fmt"
	"log"
	"net"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func (mdb *MusicDB) ZoneGetRRsets(dbzone *Zone, owner,
	rrtype string) (error, string, map[string][]dns.RR) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name),
			"", map[string][]dns.RR{}
	}

	sg := dbzone.SignerGroup()

	if sg.Name == "" || sg.Name == "---" {
		return fmt.Errorf("Zone %s has no signer group assigned", dbzone.Name),
			"", map[string][]dns.RR{}
	}

	err, rrsets := dbzone.RetrieveRRset(owner, dns.StringToType[rrtype])
	return err, "", rrsets
}

func (mdb *MusicDB) ZoneCopyRRset(tx *sql.Tx, dbzone *Zone, owner,
	rrtype, fromsigner, tosigner string) (error, string) {
	if !dbzone.Exists {
		return fmt.Errorf("Zone %s unknown", dbzone.Name), ""
	}

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return err, "fail"
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	fs, err := mdb.GetSignerByName(tx, fromsigner, false) // not apisafe
	if err != nil {
		return fmt.Errorf("Signer %s (copying from) is unknown.", fromsigner), ""
	}
	ts, err := mdb.GetSignerByName(tx, tosigner, false) // not apisafe
	if err != nil {
		return fmt.Errorf("Signer %s (copying to) is unknown.", tosigner), ""
	}

	err, rrs := fs.RetrieveRRset(dbzone.Name, owner, dns.StringToType[rrtype])
	if err != nil {
		return fmt.Errorf("Error from RetrieveRRset: %v", err), ""
	}

	if len(rrs) == 0 {
		return fmt.Errorf("ZoneCopyRRset: No records returned in query to signer %s."),
			""
	}

	err = ts.UpdateRRset(dbzone.Name, owner, dns.StringToType[rrtype], rrs)
	if err != nil {
		return fmt.Errorf("Error from UpdateRRset: %v", err), ""
	}
	return err, ""
}

func (z *Zone) RetrieveRRset(owner string, rrtype uint16) (error, map[string][]dns.RR) {
	sg := z.SignerGroup()
	signers := sg.Signers()

	fmt.Printf("%sRetrieveRRset: retrieving data from all signers in signer group %s\n",
		z.Name, sg.Name)

	var rrmap = map[string][]dns.RR{}

	// fmt.Printf("RetRRset: zone %s has signer group %s: %v\n", z.Name, sg.Name, sg)
	// fmt.Printf("RetrieveRRset: signers: %v\n", signers)

	var err error
	var rrs []dns.RR

	for _, s := range signers {
		err, rrs = s.RetrieveRRset(z.Name, owner, rrtype)
		if err != nil {
			return err, map[string][]dns.RR{}
		} else {
			rrmap[s.Name] = rrs
		}
	}
	return nil, rrmap
}

// SignerRRsets is used to return the RRset for a particular ownername and RRtype from one
// or more signers

type SignerRRsets map[string][]dns.RR

func (s *Signer) RetrieveRRset(zone, owner string, rrtype uint16) (error, []dns.RR) {
	fmt.Printf("Signer %s: retrieving RRset '%s %s'\n", s.Name, owner, dns.TypeToString[rrtype])
	updater := GetUpdater(s.Method)
	return updater.FetchRRset(s, zone, zone, rrtype)
}

func StripDot(fqdn string) string {
	if string(fqdn[len(fqdn)-1]) == "." {
		foo := fqdn[:len(fqdn)-1]
		// fmt.Printf("StripDot: changed '%s' to '%s'\n", fqdn, foo)
		return foo
	}
	// fmt.Printf("StripDot: '%s' does not end in '.'. No change.\n", fqdn)
	return fqdn
}

func (s *Signer) UpdateRRset(zone, owner string, rrtype uint16, rrs []dns.RR) error {
	switch s.Method {
	case "ddns":
		// return DNSUpdateRRset(s, owner, rrtype)
		return fmt.Errorf(
			"Signer %s has method=ddns, which is not yet implemented.",
			s.Name)
	case "desec-api":
		// XXX: old code that should be ripped out
		//		err, _ := DesecUpdateRRset(s, StripDot(zone), StripDot(owner), rrtype, rrs)
		//		return err
	default:
		return fmt.Errorf("Unknown RRset retrieval method: %s", s.Method)
	}
	return nil
}

func DNSFilterRRsetOnType(rrs []dns.RR, rrtype uint16) []dns.RR {
	var out []dns.RR

	for _, r := range rrs {
		rr := r.String()
		if r.Header().Rrtype == rrtype {
			out = append(out, r)
		} else {
			// fmt.Printf("Not saving RR: %s\n", rr)
			_ = rr
		}
	}
	return out
}

func (mdb *MusicDB) WriteRRs(signer *Signer, owner, zone string,
	rrtype uint16, rrs []dns.RR) error {

	var tx *sql.Tx
	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("WriteRRs: Error from mdb.StartTransaction(): %v\n", err)
		return err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	const delsql = "DELETE FROM records WHERE zone=? AND owner=? AND signer=? AND rrtype=?"

	_, err = tx.Exec(delsql, zone, owner, signer.Name, int(rrtype))
	if CheckSQLError("WriteRRs", delsql, err, false) {
		return err
	}

	addsql := "INSERT INTO records (zone, owner, signer, rrtype, rdata) VALUES (?, ?, ?, ?, ?)"

	addstmt, err := tx.Prepare(addsql)
	if err != nil {
		log.Printf("mdb.WriteRRs: Error from db.Prepare(%s): %v", addsql, err)
	}

	for _, r := range rrs {
		rr := r.String()
		if r.Header().Rrtype == rrtype {
			_, err = addstmt.Exec(zone, owner, signer.Name, int(rrtype), rr)
			if CheckSQLError("WriteRRs", addsql, err, false) {
			   return err
			}
		} else {
			// if verbose {
			// fmt.Printf("Not saving RR: %s\n", rr)
			//  }
		}
	}

	return nil
}

// XXX: is this still in use?
// XXX: broken, should return a []dns.RR, not []string.
func (mdb *MusicDB) ListRRset(dbzone *Zone, signer, ownername, rrtype string) (error, string, []string) {
	var rrs []string
	RRtype := dns.StringToType[rrtype]

	const sql = "SELECT rdata FROM records WHERE owner=? AND signer=? AND rrtype=?"
	stmt, err := mdb.Prepare(sql)
	if err != nil {
		fmt.Printf("ListRRset: Error from db.Prepare: %v\n", err)
	}

	rows, err := stmt.Query(ownername, signer, RRtype)
	defer rows.Close()

	if CheckSQLError("ListRRset", sql, err, false) {
		return err, "", rrs
	} else {
		var rdata string
		for rows.Next() {
			err := rows.Scan(&rdata)
			// fmt.Printf("ListRRset: rdata: %s\n", rdata)
			if err != nil {
				log.Fatalf("ListRRset: Error from rows.Next(): %v", err)
			} else {
				rrs = append(rrs, rdata)
			}
		}
	}
	return nil, "", rrs
}

func AuthoritativeDNSQuery(qname, nameserver string, rrtype uint16, verbose bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), rrtype)
	m.SetEdns0(4096, true)
	r, err := dns.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil && verbose {
		log.Printf("AuthDNSQuery: Error from dns.Exchange: %v", err)
	}
	return r
}

func RecursiveDNSQuery(qname, nameserver string, rrtype uint16, verbose bool) (*dns.Msg, bool) {
	var validated bool
	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)
	m.SetEdns0(4096, true)
	r, err := dns.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil && verbose {
		log.Printf("RecursiveDNSQuery: Error from dns.Exchange: %v", err)
	}
	if (r != nil) && r.MsgHdr.AuthenticatedData {
		validated = true
	}
	return r, validated
}

func (mdb *MusicDB) GetMeta(tx *sql.Tx, z *Zone, key string) (string, bool, error) {

	localtx, tx, err := mdb.StartTransaction(tx)
	if err != nil {
		log.Printf("ZoneJoinGroup: Error from mdb.StartTransaction(): %v\n", err)
		return "", false, err
	}
	defer mdb.CloseTransaction(localtx, tx, err)

	const sqlq = "SELECT value FROM metadata WHERE zone=? AND key=?"

	row := tx.QueryRow(sqlq, z.Name, key)

	var value string
	switch err = row.Scan(&value); err {
	case sql.ErrNoRows:
		// fmt.Printf("GetMeta: Key \"%s\" does not exist\n", key)
		return "", false, nil

	case nil:
		// fmt.Printf("GetMeta: found key %s\n", key)
		return value, true, nil
	}
	return "", false, nil
}
