// Package dimse implements the DICOM upper-layer (DIMSE) protocol handshake
// needed to fingerprint a DICOM SCP: A-ASSOCIATE-RQ, parse the AC/RJ response,
// then an optional C-ECHO verification round-trip.
//
// This is the recon slice of dimse-pwn's probe_echo, hand-rolled on raw sockets
// (no pynetdicom). Reference: DICOM PS3.8 (upper layer) and PS3.7 (DIMSE-C).
package dimse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// Well-known DICOM UIDs.
const (
	applicationContextUID = "1.2.840.10008.3.1.1.1"
	verificationSOPClass  = "1.2.840.10008.1.1"     // "are you a DICOM node" SOP class
	implicitVRLittleEnd   = "1.2.840.10008.1.2"     // every conformant node speaks this
	explicitVRLittleEnd   = "1.2.840.10008.1.2.1"

	// Our SCU identity. Under the Medical Connections free UID root; identifies
	// the scanner without impersonating a real product.
	ourImplClassUID = "1.2.826.0.1.3680043.9.7281.0"
	ourImplVersion  = "ZGRAB2_DIMSE"

	presentationContextID = 0x01 // odd, per PS3.8
	maxPDUReceive         = 16384
)

// PDU types (PS3.8 §9.3).
const (
	pduAssociateRQ = 0x01
	pduAssociateAC = 0x02
	pduAssociateRJ = 0x03
	pduDataTF      = 0x04
	pduReleaseRQ   = 0x05
	pduAbort       = 0x07
)

// Results is the JSON output of a DIMSE scan.
type Results struct {
	Established            bool    `json:"established"`
	CalledAE               string  `json:"called_ae,omitempty"`
	CallingAE              string  `json:"calling_ae,omitempty"`
	ImplementationClassUID string  `json:"implementation_class_uid,omitempty"`
	ImplementationVersion  string  `json:"implementation_version,omitempty"`
	MaxPDULength           uint32  `json:"max_pdu_length,omitempty"`
	AcceptedTransferSyntax string  `json:"accepted_transfer_syntax,omitempty"`
	VerificationAccepted   bool    `json:"verification_accepted"`
	EchoStatus             *uint16 `json:"echo_status,omitempty"` // 0x0000 == success

	Rejected     bool   `json:"rejected,omitempty"`
	Aborted      bool   `json:"aborted,omitempty"`
	RejectResult uint8  `json:"reject_result,omitempty"`
	RejectSource uint8  `json:"reject_source,omitempty"`
	RejectReason uint8  `json:"reject_reason,omitempty"`
	RejectDetail string `json:"reject_detail,omitempty"`
}

// Associate performs the full recon handshake against conn and fills a Results.
// It returns a non-nil error only when the peer does not speak DICOM (garbage
// PDU); a clean rejection or abort is a successful DICOM detection.
func Associate(conn net.Conn, callingAE, calledAE string) (*Results, error) {
	res := &Results{CalledAE: calledAE, CallingAE: callingAE}

	if _, err := conn.Write(buildAssociateRQ(callingAE, calledAE)); err != nil {
		return res, fmt.Errorf("writing A-ASSOCIATE-RQ: %w", err)
	}
	pduType, body, err := readPDU(conn)
	if err != nil {
		return res, fmt.Errorf("reading association response: %w", err)
	}

	switch pduType {
	case pduAssociateAC:
		accepted, err := parseAssociateAC(body, res)
		if err != nil {
			return res, err
		}
		res.Established = true
		if accepted {
			res.VerificationAccepted = true
			if status, err := doCEcho(conn); err == nil {
				res.EchoStatus = &status
			}
		}
		// Best-effort graceful teardown; peer may just close.
		_, _ = conn.Write([]byte{pduReleaseRQ, 0x00, 0, 0, 0, 4, 0, 0, 0, 0})
		return res, nil
	case pduAssociateRJ:
		parseAssociateRJ(body, res)
		return res, nil
	case pduAbort:
		res.Aborted = true
		return res, nil
	default:
		return res, fmt.Errorf("unexpected PDU type 0x%02x (not a DICOM peer)", pduType)
	}
}

// --- PDU I/O ---------------------------------------------------------------

// readPDU reads one upper-layer PDU: 1 type + 1 reserved + 4-byte BE length + body.
func readPDU(conn net.Conn) (byte, []byte, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[2:6])
	if length > 1<<20 { // 1 MiB sanity cap; association PDUs are tiny
		return 0, nil, fmt.Errorf("PDU length %d too large", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

// --- A-ASSOCIATE-RQ construction (PS3.8 §9.3.2) ----------------------------

func buildAssociateRQ(callingAE, calledAE string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x00, 0x01, 0x00, 0x00}) // protocol version 1 + reserved
	b.WriteString(padAE(calledAE))
	b.WriteString(padAE(callingAE))
	b.Write(make([]byte, 32)) // reserved

	b.Write(subItem(0x10, []byte(applicationContextUID)))
	b.Write(buildPresentationContextRQ())
	b.Write(buildUserInfo())

	return framePDU(pduAssociateRQ, b.Bytes())
}

func buildPresentationContextRQ() []byte {
	var pc bytes.Buffer
	pc.Write([]byte{presentationContextID, 0x00, 0x00, 0x00})
	pc.Write(subItem(0x30, []byte(verificationSOPClass)))          // abstract syntax
	pc.Write(subItem(0x40, []byte(implicitVRLittleEnd)))           // transfer syntax
	pc.Write(subItem(0x40, []byte(explicitVRLittleEnd)))
	return subItem(0x20, pc.Bytes())
}

func buildUserInfo() []byte {
	var ui bytes.Buffer
	maxLen := make([]byte, 4)
	binary.BigEndian.PutUint32(maxLen, maxPDUReceive)
	ui.Write(subItem(0x51, maxLen))
	ui.Write(subItem(0x52, []byte(ourImplClassUID)))
	ui.Write(subItem(0x55, []byte(ourImplVersion)))
	return subItem(0x50, ui.Bytes())
}

// subItem builds a variable item / sub-item: type, reserved, 2-byte BE length, value.
func subItem(itemType byte, value []byte) []byte {
	out := make([]byte, 4+len(value))
	out[0] = itemType
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

func framePDU(pduType byte, body []byte) []byte {
	out := make([]byte, 6+len(body))
	out[0] = pduType
	binary.BigEndian.PutUint32(out[2:6], uint32(len(body)))
	copy(out[6:], body)
	return out
}

func padAE(ae string) string {
	if len(ae) > 16 {
		ae = ae[:16]
	}
	return ae + strings.Repeat(" ", 16-len(ae))
}

// --- Response parsing ------------------------------------------------------

// parseAssociateAC walks the AC variable items, capturing the fingerprint
// (impl class UID, version, max PDU) and whether our verification context was
// accepted. Returns accepted==true when the presentation context result is 0.
func parseAssociateAC(body []byte, res *Results) (bool, error) {
	if len(body) < 68 {
		return false, fmt.Errorf("A-ASSOCIATE-AC too short (%d bytes)", len(body))
	}
	accepted := false
	items := body[68:] // skip protocol version + reserved + 2 AE titles + reserved
	for len(items) >= 4 {
		itemType := items[0]
		length := int(binary.BigEndian.Uint16(items[2:4]))
		if 4+length > len(items) {
			break
		}
		value := items[4 : 4+length]
		switch itemType {
		case 0x21: // presentation context (AC)
			if len(value) >= 4 && value[2] == 0x00 { // result field == acceptance
				accepted = true
				res.AcceptedTransferSyntax = firstTransferSyntax(value[4:])
			}
		case 0x50: // user information
			parseUserInfo(value, res)
		}
		items = items[4+length:]
	}
	return accepted, nil
}

func firstTransferSyntax(subItems []byte) string {
	for len(subItems) >= 4 {
		length := int(binary.BigEndian.Uint16(subItems[2:4]))
		if 4+length > len(subItems) {
			break
		}
		if subItems[0] == 0x40 {
			return trimUID(string(subItems[4 : 4+length]))
		}
		subItems = subItems[4+length:]
	}
	return ""
}

func parseUserInfo(subItems []byte, res *Results) {
	for len(subItems) >= 4 {
		itemType := subItems[0]
		length := int(binary.BigEndian.Uint16(subItems[2:4]))
		if 4+length > len(subItems) {
			break
		}
		value := subItems[4 : 4+length]
		switch itemType {
		case 0x51:
			if len(value) == 4 {
				res.MaxPDULength = binary.BigEndian.Uint32(value)
			}
		case 0x52:
			res.ImplementationClassUID = trimUID(string(value))
		case 0x55:
			res.ImplementationVersion = strings.TrimRight(string(value), " \x00")
		}
		subItems = subItems[4+length:]
	}
}

// parseAssociateRJ decodes A-ASSOCIATE-RJ (PS3.8 §9.3.4): reserved, result,
// source, reason.
func parseAssociateRJ(body []byte, res *Results) {
	res.Rejected = true
	if len(body) < 4 {
		return
	}
	res.RejectResult = body[1]
	res.RejectSource = body[2]
	res.RejectReason = body[3]
	res.RejectDetail = fmt.Sprintf("%s / %s / reason %d",
		rejectResultStr(body[1]), rejectSourceStr(body[2]), body[3])
}

func rejectResultStr(r uint8) string {
	switch r {
	case 1:
		return "rejected-permanent"
	case 2:
		return "rejected-transient"
	}
	return "unknown-result"
}

func rejectSourceStr(s uint8) string {
	switch s {
	case 1:
		return "service-user"
	case 2:
		return "service-provider(ACSE)"
	case 3:
		return "service-provider(presentation)"
	}
	return "unknown-source"
}

func trimUID(s string) string {
	return strings.TrimRight(s, " \x00")
}

// --- C-ECHO (PS3.7) --------------------------------------------------------

// DIMSE command tags (group 0000), Implicit VR Little Endian.
var (
	tagGroupLength     = [4]byte{0x00, 0x00, 0x00, 0x00}
	tagAffectedSOPClas = [4]byte{0x00, 0x00, 0x02, 0x00}
	tagCommandField    = [4]byte{0x00, 0x00, 0x00, 0x01}
	tagMessageID       = [4]byte{0x00, 0x00, 0x10, 0x01}
	tagDataSetType     = [4]byte{0x00, 0x00, 0x00, 0x08}
	tagStatus          = [4]byte{0x00, 0x00, 0x00, 0x09}
)

// doCEcho sends a C-ECHO-RQ over the accepted context and returns the status
// from the C-ECHO-RSP command set.
func doCEcho(conn net.Conn) (uint16, error) {
	if _, err := conn.Write(buildCEchoPDU()); err != nil {
		return 0, err
	}
	pduType, body, err := readPDU(conn)
	if err != nil {
		return 0, err
	}
	if pduType != pduDataTF {
		return 0, fmt.Errorf("expected P-DATA-TF, got 0x%02x", pduType)
	}
	// PDV: 4-byte BE length, 1 pcid, 1 message-control-header, then command bytes.
	if len(body) < 6 {
		return 0, fmt.Errorf("short P-DATA-TF")
	}
	pdvLen := int(binary.BigEndian.Uint32(body[0:4]))
	if 4+pdvLen > len(body) || pdvLen < 2 {
		return 0, fmt.Errorf("bad PDV length")
	}
	return findStatusElement(body[6 : 4+pdvLen])
}

func buildCEchoPDU() []byte {
	// Command elements after the group-length element.
	var cmd bytes.Buffer
	cmd.Write(dimseElement(tagAffectedSOPClas, evenPad([]byte(verificationSOPClass))))
	cmd.Write(dimseElement(tagCommandField, u16le(0x0030)))  // C-ECHO-RQ
	cmd.Write(dimseElement(tagMessageID, u16le(0x0001)))
	cmd.Write(dimseElement(tagDataSetType, u16le(0x0101)))   // no data set

	groupLen := u32le(uint32(cmd.Len()))
	var full bytes.Buffer
	full.Write(dimseElement(tagGroupLength, groupLen))
	full.Write(cmd.Bytes())

	// PDV = pcid + message-control-header(0x03: command, last fragment) + command.
	pdv := make([]byte, 2+full.Len())
	pdv[0] = presentationContextID
	pdv[1] = 0x03
	copy(pdv[2:], full.Bytes())

	pdvItem := make([]byte, 4+len(pdv))
	binary.BigEndian.PutUint32(pdvItem[0:4], uint32(len(pdv)))
	copy(pdvItem[4:], pdv)

	return framePDU(pduDataTF, pdvItem)
}

// findStatusElement scans an Implicit VR LE command set for (0000,0900) Status.
func findStatusElement(cmd []byte) (uint16, error) {
	for len(cmd) >= 8 {
		length := int(binary.LittleEndian.Uint32(cmd[4:8]))
		if 8+length > len(cmd) {
			break
		}
		if [4]byte{cmd[0], cmd[1], cmd[2], cmd[3]} == tagStatus && length >= 2 {
			return binary.LittleEndian.Uint16(cmd[8:10]), nil
		}
		cmd = cmd[8+length:]
	}
	return 0, fmt.Errorf("no status element in C-ECHO-RSP")
}

// dimseElement encodes one Implicit VR LE element: tag (4) + 4-byte LE length + value.
func dimseElement(tag [4]byte, value []byte) []byte {
	out := make([]byte, 8+len(value))
	copy(out[0:4], tag[:])
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}

func u16le(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// evenPad pads a UID value to even length with a trailing null, per DICOM.
func evenPad(b []byte) []byte {
	if len(b)%2 != 0 {
		return append(b, 0x00)
	}
	return b
}
