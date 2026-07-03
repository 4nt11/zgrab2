// Package mllp provides a zgrab2 module that fingerprints HL7 interface engines
// speaking MLLP (Minimal Lower Layer Protocol).
//
// Default Port: 2575 (TCP) — the IANA-registered HL7-over-MLLP port.
//
// The scan sends a single minimal HL7 v2 message and parses the ACK, reporting
// the acknowledging application/facility, HL7 version, and MSA acknowledgement
// code. The default message type (ZZZ^Z99) is deliberately unrouted: the engine
// ACKs it and leaks its MSH fingerprint without invoking any ADT/order/observation
// handler that would mutate clinical state. Do NOT set --message-type to an active
// trigger against systems you are not authorized to modify.
package mllp

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the mllp scan module.
type Flags struct {
	zgrab2.BaseFlags  `group:"Basic Options"`
	MessageType       string `long:"message-type" default:"ZZZ^Z99" description:"HL7 MSH-9 message type for the probe. Default is an unrouted type that fingerprints the engine with no side effects; active triggers (ADT/ORU/RDE/ORM) may mutate clinical state."`
	UseTLS            bool   `long:"use-tls" description:"Wrap the connection in TLS (MLLPS / HL7-over-TLS) before sending the probe. Loads TLS module command options."`
	AllowTLSDowngrade bool   `long:"allow-tls-downgrade" description:"If --use-tls is set and the TLS handshake fails, fall back to plaintext instead of aborting. Requires --use-tls."`
	zgrab2.TLSFlags   `group:"TLS Options"`
}

// Validate rejects incompatible flag combinations.
func (flags Flags) Validate(_ []string) error {
	if flags.AllowTLSDowngrade && !flags.UseTLS {
		return errors.New("--allow-tls-downgrade requires --use-tls")
	}
	return nil
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("mllp", "HL7 MLLP (health interface engine)", "Send a minimal HL7 v2 message over MLLP and fingerprint the ACK. Default port 2575.", 2575)
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

// Scan sends the MLLP probe and returns a *Results.
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

	res, err := Probe(conn, scanner.config.MessageType)
	if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok && res != nil {
		res.TLSLog = tlsConn.GetLog()
	}
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, res, fmt.Errorf("mllp probe of %v failed: %w", target.String(), err)
	}
	return zgrab2.SCAN_SUCCESS, res, nil
}
