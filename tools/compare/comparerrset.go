package compare

// https://www.rfc-editor.org/rfc/rfc2181

import (
	"github.com/miekg/dns"
)

// CompareRRset compares two RRsets and returns if they are equal or not,
//   include the non-matching RRs in a slice per RRset.
func CompareRRset(rrset1, rrset2 []dns.RR) (bool, []dns.RR, []dns.RR) {
	allEqual := true
	var equal bool
	var rrset1Extra []dns.RR
	var rrset2Extra []dns.RR

	for _, rr1 := range rrset1 {
		equal = false
		for _, rr2 := range rrset2 {
			if dns.IsDuplicate(rr1, rr2) {
				equal = true
				break
			}
		}
		if !equal {
			// have not found rr1 in rrset2
			rrset1Extra = append(rrset1Extra, rr1)
			allEqual = false
		}
	}
	for _, rr2 := range rrset2 {
		equal = false
		for _, rr1 := range rrset1 {
			if dns.IsDuplicate(rr2, rr1) {
				equal = true
				break
			}
		}
		if !equal {
			// have not found rr2 in rrset1
			rrset2Extra = append(rrset2Extra, rr2)
			allEqual = false
		}
	}

	return allEqual, rrset1Extra, rrset2Extra
}
