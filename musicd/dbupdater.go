/*
 * 
 */

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/DNSSEC-Provisioning/music/common"
)

func dbUpdater(conf *Config) {

     log.Printf("dbUpdater: Starting DB Update Service.")

	mdb := conf.Internal.MusicDB

	dbupdateC := make(chan music.DBUpdate, 5)
	conf.Internal.DBUpdateC = dbupdateC
	mdb.UpdateC = dbupdateC

	const ZSMsql = "INSERT OR REPLACE INTO metadata (zone, key, time, value) VALUES (?, ?, datetime('now'), ?)"

	mstmt, err := mdb.Prepare(ZSMsql)
	if err != nil {
		log.Fatalf("dbUpdater: Error from db.Prepare(%s) 1: %v\n", ZSMsql, err)
	}

	const DSsql = "UPDATE zones SET fsmstatus='blocked' WHERE name=?"
	blockstmt, err1 := mdb.Prepare(DSsql)
	if err1 != nil {
		log.Fatalf("dbUpdater: Error from db.Prepare(%s): %v", DSsql, err)
	}

	ticker := time.NewTicker(2 * time.Second)

	queue := []music.DBUpdate{}
	var update music.DBUpdate

	RunDBQueue := func() {
		for {
			if len(queue) == 0 {
				// log.Printf("RunDBQueue: DBQueue is empty")
				break
			}
			u := queue[0]
			t := u.Type

			tx, err := mdb.Begin()
			if err != nil {
				log.Printf("RunDBQueue: Error from mdb.Begin(): %v", err)
			}

			switch t {
			case "STOPREASON":
				_, err := mstmt.Exec(u.Zone, u.Key, u.Value)
				if err != nil {
					if err.(sqlite3.Error).Code == sqlite3.ErrLocked {
						// database is locked by other connection
						log.Printf("RunDBQueue: UPDATE db locked. will try again. queue: %d",
							len(queue))
						tx.Rollback()
						return // let's try again later
					} else {
						log.Printf("RunDBQueue: UPDATE Error from sqlupdate.Exec: %v",
							err)
						return
					}
				}
				_, err = blockstmt.Exec(u.Zone)
				if err != nil {
					if err.(sqlite3.Error).Code == sqlite3.ErrLocked {
						// database is locked by other connection
						log.Printf("RunDBQueue: UPDATE db locked. will try again. queue: %d",
							len(queue))
						tx.Rollback()
						return // let's try again later
					} else {
						log.Printf("RunDBQueue: UPDATE Error from sqlupdate.Exec: %v",
							err)
						return
					}
				}
			}

			err = tx.Commit()
			if err != nil {
				log.Printf("dbUpdater: RunQueue: Error from tx.Commit: %v", err)
			} else {
			        log.Printf("dbUpdater: Updated zone %s stop-reason to '%s'", u.Zone, u.Value)			
				queue = queue[1:] // only drop item after successful commit
			}
		}
	}

	for {
		select {
		case update = <-dbupdateC:
			queue = append(queue, update)
			RunDBQueue()

		case <-ticker.C:
			RunDBQueue()
		}
	}
}
