// Package dimse provides a zgrab2 module that scans for DICOM DIMSE services
// (medical imaging / PACS nodes).
//
// Default Port: 11112 (TCP) — the common non-privileged DICOM port; the classic
// registered port is 104. Override with --port.
//
// The scan performs a single DICOM association (A-ASSOCIATE-RQ) requesting the
// Verification SOP class, then fingerprints the acceptor (implementation class
// UID, version name, max PDU) and, if the context is accepted, sends a C-ECHO.
// A clean rejection or abort still counts as a positive DICOM detection.
package dimse

import (
	"context"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the dimse scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	CallingAE        string `long:"calling-ae" default:"ZGRAB2" description:"Calling (source) AE title, max 16 chars."`
	CalledAE         string `long:"called-ae" default:"ANY-SCP" description:"Called (destination) AE title, max 16 chars. Some SCPs reject a non-matching title."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("dimse", "DICOM DIMSE (medical imaging / PACS)", "Associate with a DICOM SCP, fingerprint it, and C-ECHO. Default port 11112.", 11112)
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// Scan performs the DICOM association handshake and returns a *Results.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing target %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	res, err := Associate(conn, scanner.config.CallingAE, scanner.config.CalledAE)
	if err != nil {
		// A protocol/IO error against a peer that never spoke valid DICOM.
		return zgrab2.SCAN_PROTOCOL_ERROR, res, fmt.Errorf("dimse association with %v failed: %w", target.String(), err)
	}
	// AC, RJ, or ABORT all confirm a DICOM node.
	return zgrab2.SCAN_SUCCESS, res, nil
}
