
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package main

import (
        "fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/miekg/dns"
)

type NotifyItem struct {
     ZoneName	string
     NotifyType	uint16	// dns.TypeCDS | dns.TypeCSYNC | dns.TypeDNSKEY | dns.TypeSOA
     Parent	string
     ParentNotifyAddr		string	// ip:port
     Delay			int	// wait this many seconds until sending NOTIFY
}

func NotifyEngine(conf *Config, stopch chan struct{}) {
	var ntype uint16
	cdsdelay := viper.GetInt("notifyengine.delay.cds")
	csyncdelay := viper.GetInt("notifyengine.delay.cds")
	var zonename string
	var checkitem NotifyItem
	checkch := conf.Internal.NotifyQueue

	PendingCDSNotifies := make(map[string]*NotifyItem, 5)
	PendingCSYNCNotifies := make(map[string]*NotifyItem, 5)

	if !viper.GetBool("notifyengine.active") {
		log.Printf("NotifyEngine is NOT active.")
		for {
			select {
			case <-checkch: // ensure that we keep reading to keep the
				continue // channel open (otherwise other parts of MUSIC
			} // may block)
		}
	}

	log.Printf("Starting NotifyEngine (will run once every second)")

	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case checkitem = <-checkch:
			zonename = checkitem.ZoneName
			ntype = checkitem.NotifyType
			if zonename != "" {
				log.Printf("NotifyEngine: Will send a NOTIFY(%S) to the parent of '%s'.",
					dns.TypeToString[ntype], zonename)
				switch ntype {
				case dns.TypeCDS:
				     checkitem.Delay = cdsdelay
				     PendingCDSNotifies[zonename] = &checkitem
				case dns.TypeCSYNC:
				     checkitem.Delay = csyncdelay
				     PendingCSYNCNotifies[zonename] = &checkitem
				default:
				     log.Fatalf("NotifyEngine: Don't know how to deal with NOTIFY(%s)",
				     			       dns.TypeToString[ntype])
				}
			}

		case <-ticker.C:
			for _, v := range PendingCDSNotifies {
			    v.Delay--
			    if v.Delay <= 0 {
			       go v.Send()
			    }
			    delete(PendingCDSNotifies, v.ZoneName)
			}
			for _, v := range PendingCSYNCNotifies {
			    v.Delay--
			    if v.Delay <= 0 {
			       go v.Send()
			    }
			    delete(PendingCSYNCNotifies, v.ZoneName)
			}

		case <-stopch:
			ticker.Stop()
			log.Println("FSM Engine: stop signal received.")
			return
		}
	}
}

// 1. Figure out who the parent is.
// 2. Lookup the notification address
// 3. Send the NOTIFY (if no response then resend twice, for a total of 3 times)
// 4. Declare victory and terminate.
func (ni *NotifyItem) Send() {
     log.Printf("Sending NOTIFY(%s) for zone %s", dns.TypeToString[ni.NotifyType], ni.ZoneName)

     imr := viper.GetString("notifyengine.imr")
	if imr == "" {
		imr = viper.GetString("notifyengine.imr")
		if imr != "" && verbose {
			fmt.Printf("Warning: IMR not specified. Using IMR from config: %s\n", imr)
		} else {
			if verbose {
				fmt.Printf("Error: IMR not specified and no IMR in config. Terminating.\n")
			}
			os.Exit(1)
		}
	}

	parentzone := ParentZone(ni.ZoneName, imr)
	var qname string

	switch ni.NotifyType {
	case dns.TypeCDS:
		qname = fmt.Sprintf("_cds-notifications.%s", parentzone)
	case dns.TypeCSYNC:
		qname = fmt.Sprintf("_csync-notifications.%s", parentzone)
	case dns.TypeDNSKEY:
		log.Printf("This is a sideways NOTIFY for a Multi-Signer setup. Where do you want to send it?\n")
	case dns.TypeSOA:
		log.Printf("This is a normal NOTIFY. Where do you want to send it?\n")
	default:
		log.Printf("Unknown NOTIFY RRtype: %s. Terminating.\n", dns.TypeToString[ni.NotifyType])
	}

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeSRV)
	res, err := dns.Exchange(m, imr)
	if err != nil {
		log.Fatalf("Error from dns.Exchange(%s, SRV): %v", ni.ZoneName, err)
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error: Query for %s SRV received rcode: %s",
			qname, dns.RcodeToString[res.Rcode])
	}

	if len(res.Answer) > 0 {
		rr := res.Answer[0]
		if srv, ok := rr.(*dns.SRV); ok {
			// if debug {
				fmt.Printf("Looking up parent notification address:\n%s\n", rr.String())
			// }

			msg := fmt.Sprintf("Sending %s Notification for zone %s to: %s:%d",
				strings.ToUpper(dns.TypeToString[ni.NotifyType]),
				ni.ZoneName, srv.Target, srv.Port)

			m = new(dns.Msg)
			m.SetNotify(ni.ZoneName)
			m.Question[0] = dns.Question{ni.ZoneName, ni.NotifyType, dns.ClassINET}
			res, err = dns.Exchange(m, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
			if err != nil {
				log.Fatalf("Error from dns.Exchange(%s, SRV): %v", ni.ZoneName, err)
			}

			if res.Rcode != dns.RcodeSuccess {
				fmt.Printf(msg+"... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
				log.Fatalf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
			} else {
				fmt.Printf(msg + "... and got rcode NOERROR back (good)\n")
			}
		} else {
		       log.Fatalf("Error: answer is not an SRV RR: %s", rr.String())
		}
	}
}

func ParentZone(zone, imr string) string {
     return "foffa"
}