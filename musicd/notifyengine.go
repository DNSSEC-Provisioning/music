//
// Johan Stenstam, johan.stenstam@internetstiftelsen.se
//

package main

import (
	"log"
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

func (ni *NotifyItem) Send() {
     log.Printf("Sending NOTIFY(%s) for zone %s", dns.TypeToString[ni.NotifyType], ni.ZoneName)
}