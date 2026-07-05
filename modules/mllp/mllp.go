// Package mllp implements the MLLP (Minimal Lower Layer Protocol) framing and
// the tiny slice of HL7 v2 parsing needed to fingerprint an HL7 interface
// engine: send a minimal message, read the ACK, and pull the acknowledging
// application/facility, version, and MSA acknowledgement code out of it.
//
// MLLP frame (HL7 PS, "MLLP Release 2"): <SB> payload <EB> <CR>, where
// SB = 0x0B, EB = 0x1C, CR = 0x0D. HL7 v2 segments within the payload are
// CR-separated; fields are separated by the char in MSH-1 (canonically '|').
package mllp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/zmap/zgrab2"
)

const (
	sb byte = 0x0b // start block
	eb byte = 0x1c // end block
	cr byte = 0x0d // carriage return (segment terminator / frame trailer)

	// maxResponse caps how much we read while framing, so a hostile or
	// non-MLLP peer can't stream forever.
	maxResponse = 1 << 20
)

// Results is the JSON output of an MLLP scan.
type Results struct {
	Detected             bool   `json:"detected"`                        // MLLP listener confirmed (HL7 ACK or MLLP framing)
	DetectionMethod      string `json:"detection_method,omitempty"`      // "hl7-ack" (tier 1) or "mllp-frame" (tier 2)
	ProbeType            string `json:"probe_type,omitempty"`            // MSH-9 of the probe message that got the detection
	AckCode              string `json:"ack_code,omitempty"`              // MSA-1: AA/AE/AR/CA/CE/CR
	AckText              string `json:"ack_text,omitempty"`              // MSA-3
	SendingApplication   string `json:"sending_application,omitempty"`   // response MSH-3
	SendingFacility      string `json:"sending_facility,omitempty"`      // response MSH-4
	ReceivingApplication string `json:"receiving_application,omitempty"` // response MSH-5
	ReceivingFacility    string `json:"receiving_facility,omitempty"`    // response MSH-6
	MessageType          string `json:"message_type,omitempty"`          // response MSH-9
	ProcessingID         string `json:"processing_id,omitempty"`         // response MSH-11
	Version              string `json:"version,omitempty"`               // response MSH-12
	ControlID            string `json:"control_id,omitempty"`            // response MSH-10
	ErrText              string `json:"err_text,omitempty"`              // ERR-8 (or ERR-3) if present
	Raw                  string `json:"raw,omitempty"`                   // de-framed HL7 banner

	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"` // populated when --use-tls
}

// Probe sends a minimal HL7 message of the given type and parses the ACK.
// messageType should be a benign, read-only or unrouted type (e.g. "QBP^Q11")
// — never an order/observation/ADT that a real engine would act on.
func Probe(conn net.Conn, messageType string) (*Results, error) {
	res := &Results{}
	if _, err := conn.Write(frame(buildProbe(messageType))); err != nil {
		return res, fmt.Errorf("writing MLLP probe: %w", err)
	}
	payload, framed, err := readFrame(conn)
	if err != nil {
		return res, fmt.Errorf("reading MLLP response: %w", err)
	}
	res.Raw = payload
	// Tier 1: a parseable HL7 ACK (MSH present) — the strongest signal.
	if parseHL7(payload, res) {
		res.Detected = true
		res.DetectionMethod = "hl7-ack"
		return res, nil
	}
	// Tier 2: the response arrived wrapped in MLLP framing (<SB>...) but wasn't a
	// parseable HL7 ACK — e.g. a misconfigured engine returning an empty frame, or
	// a non-standard NAK. Only an MLLP speaker opens a response with <SB>, so this
	// is still a positive identification. Cuts false negatives on real-world hosts
	// that don't return a clean ACK.
	if framed {
		res.Detected = true
		res.DetectionMethod = "mllp-frame"
		return res, nil
	}
	return res, errors.New("response is neither HL7 nor MLLP-framed")
}

// buildProbe constructs a minimal but well-formed HL7 v2 MSH message.
// Processing ID is "T" (test/debug), and messageType defaults to an unrouted
// type so the engine ACKs the fingerprint without invoking a real handler.
func buildProbe(messageType string) string {
	ts := time.Now().UTC().Format("20060102150405")
	// Fields: MSH-1='|' (implicit), MSH-2 encoding, MSH-3/4 sender, MSH-5/6 empty,
	// MSH-7 timestamp, MSH-9 type, MSH-10 control id, MSH-11 processing id, MSH-12 version.
	return "MSH|^~\\&|ZGRAB2|ZGRAB2|||" + ts + "||" + messageType + "|ZGRAB2" + ts + "|T|2.5"
}

// --- MLLP framing ----------------------------------------------------------

func frame(payload string) []byte {
	out := make([]byte, 0, len(payload)+3)
	out = append(out, sb)
	out = append(out, payload...)
	out = append(out, eb, cr)
	return out
}

// readFrame reads until the <EB><CR> trailer and returns the de-framed payload.
// A leading <SB> is stripped; trailing framing bytes are removed. framed reports
// whether the response opened with <SB> — the MLLP signature — which lets the
// caller detect a listener even when no parseable HL7 ACK comes back.
func readFrame(conn net.Conn) (payload string, framed bool, err error) {
	var buf bytes.Buffer
	tmp := make([]byte, 512)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			// Only an MLLP speaker opens its response with <SB>; that byte alone
			// is the protocol signature even if a parseable HL7 ACK never arrives.
			framed = buf.Bytes()[0] == sb
			if i := bytes.IndexByte(buf.Bytes(), eb); i >= 0 {
				return string(stripFraming(buf.Bytes()[:i])), framed, nil
			}
			if buf.Len() > maxResponse {
				return "", framed, fmt.Errorf("response exceeded %d bytes without EB", maxResponse)
			}
		}
		if rerr != nil {
			if rerr == io.EOF && buf.Len() > 0 {
				// Peer closed without a proper trailer; return what we framed.
				return string(stripFraming(buf.Bytes())), framed, nil
			}
			return "", framed, rerr
		}
	}
}

func stripFraming(b []byte) []byte {
	if len(b) > 0 && b[0] == sb {
		b = b[1:]
	}
	return bytes.Trim(b, string([]byte{cr, eb}))
}

// --- HL7 v2 parsing (MSH + MSA only) ---------------------------------------

// parseHL7 walks the CR-separated segments, filling res from MSH and MSA.
// Returns false if no MSH segment is present.
func parseHL7(payload string, res *Results) bool {
	// Segments may be CR, LF, or CRLF separated in the wild.
	segments := strings.FieldsFunc(payload, func(r rune) bool { return r == '\r' || r == '\n' })
	foundMSH := false
	for _, seg := range segments {
		switch {
		case strings.HasPrefix(seg, "MSH"):
			foundMSH = true
			parseMSH(seg, res)
		case strings.HasPrefix(seg, "MSA"):
			parseMSA(seg, res)
		case strings.HasPrefix(seg, "ERR"):
			parseERR(seg, res)
		}
	}
	return foundMSH
}

// parseMSH extracts the fingerprint fields. In MSH the field separator itself
// is MSH-1, so splitting on it yields parts[0]="MSH", parts[1]=MSH-2, and
// field N maps to parts[N-1].
func parseMSH(seg string, res *Results) {
	if len(seg) < 4 {
		return
	}
	sep := string(seg[3]) // char immediately after "MSH" is the field separator
	f := strings.Split(seg, sep)
	res.SendingApplication = field(f, 2)   // MSH-3
	res.SendingFacility = field(f, 3)      // MSH-4
	res.ReceivingApplication = field(f, 4) // MSH-5
	res.ReceivingFacility = field(f, 5)    // MSH-6
	res.MessageType = field(f, 8)          // MSH-9
	res.ControlID = field(f, 9)            // MSH-10
	res.ProcessingID = field(f, 10)        // MSH-11
	res.Version = field(f, 11)             // MSH-12
}

// parseMSA extracts the acknowledgement code and text. MSA-1 = parts[1].
func parseMSA(seg string, res *Results) {
	f := strings.Split(seg, "|")
	res.AckCode = field(f, 1) // MSA-1
	res.AckText = field(f, 3) // MSA-3
}

// parseERR captures the error text some engines return: ERR-8 (user message),
// falling back to ERR-3 (error code).
func parseERR(seg string, res *Results) {
	f := strings.Split(seg, "|")
	if t := field(f, 8); t != "" {
		res.ErrText = t
	} else {
		res.ErrText = field(f, 3)
	}
}

func field(parts []string, i int) string {
	if i < len(parts) {
		return strings.TrimSpace(parts[i])
	}
	return ""
}
