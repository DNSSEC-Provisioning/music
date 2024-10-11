/*
 * Johan Stenstam, johani@johani.org
 */
package music

const (
	SignerJoinGroupProcess  = "add-signer"
	SignerLeaveGroupProcess = "remove-signer"
	VerifyZoneInSyncProcess = "verify-zone-sync"

	SignerGroupMinimumSigners = 1
)

const (
	DefaultCfgFile        = "/etc/music/musicd.yaml"
	DefaultSidecarCfgFile = "/etc/music/music-sidecar.yaml"
	DefaultTdnsCfgFile    = "/etc/music/tdns.yaml"        // everything TDNS related
	DefaultZonesCfgFile   = "/etc/music/music-zones.yaml" // Zones that MUSIC sidecare should serve; may be empty
)

type GlobalStuff struct {
	Verbose	bool
	Debug	bool
}

var Globals GlobalStuff
