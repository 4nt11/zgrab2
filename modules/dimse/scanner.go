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
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the dimse scan module.
type Flags struct {
	zgrab2.BaseFlags  `group:"Basic Options"`
	CallingAE         string `long:"calling-ae" default:"ZGRAB2" description:"Calling (source) AE title, max 16 chars."`
	CalledAE          string `long:"called-ae" default:"ANY-SCP" description:"Called (destination) AE title, max 16 chars. Some SCPs reject a non-matching title."`
	UseTLS            bool   `long:"use-tls" description:"Wrap the connection in TLS (DICOM-TLS, e.g. port 2762) before the association. Loads TLS module command options."`
	AllowTLSDowngrade bool   `long:"allow-tls-downgrade" description:"If --use-tls is set and the TLS handshake fails, fall back to plaintext instead of aborting. Requires --use-tls."`
	zgrab2.TLSFlags   `group:"TLS Options"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("dimse", "DICOM DIMSE (medical imaging / PACS)", "Associate with a DICOM SCP, fingerprint it, and C-ECHO. Default port 11112.", 11112)
}

// Validate enforces the DICOM AE-title constraints (PS3.8 §9.3.2): 1–16
// characters, not all whitespace, and free of the backslash and control
// characters that are illegal in the DICOM default character repertoire.
func (flags Flags) Validate(_ []string) error {
	if flags.AllowTLSDowngrade && !flags.UseTLS {
		return errors.New("--allow-tls-downgrade requires --use-tls")
	}
	if err := validateAETitle("calling-ae", flags.CallingAE); err != nil {
		return err
	}
	return validateAETitle("called-ae", flags.CalledAE)
}

func validateAETitle(name, ae string) error {
	if len(ae) < 1 || len(ae) > 16 {
		return fmt.Errorf("--%s must be 1-16 characters, got %d", name, len(ae))
	}
	if strings.TrimSpace(ae) == "" {
		return fmt.Errorf("--%s must not be all whitespace", name)
	}
	for _, r := range ae {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("--%s contains an illegal character %q", name, r)
		}
	}
	return nil
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
		TLSFlags:                        &f.TLSFlags,
		TLSEnabled:                      f.UseTLS,
		NeedSeparateL4Dialer:            f.AllowTLSDowngrade,
	}
	return nil
}

// Scan performs the DICOM association handshake and returns a *Results.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var conn net.Conn
	var err error
	if scanner.config.AllowTLSDowngrade {
		conn, _, err = dialGroup.DialTLSDowngrade(ctx, target, true)
	} else {
		conn, err = dialGroup.Dial(ctx, target)
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing target %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	res, err := Associate(conn, scanner.config.CallingAE, scanner.config.CalledAE)
	if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok && res != nil {
		res.TLSLog = tlsConn.GetLog()
	}
	if err != nil {
		// A protocol/IO error against a peer that never spoke valid DICOM.
		return zgrab2.SCAN_PROTOCOL_ERROR, res, fmt.Errorf("dimse association with %v failed: %w", target.String(), err)
	}
	// AC, RJ, or ABORT all confirm a DICOM node.
	return zgrab2.SCAN_SUCCESS, res, nil
}
