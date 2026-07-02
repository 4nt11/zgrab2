package dimse

import "testing"

// TestAssociateRQFraming checks the A-ASSOCIATE-RQ header and length framing.
func TestAssociateRQFraming(t *testing.T) {
	rq := buildAssociateRQ("ZGRAB2", "ANY-SCP")
	if rq[0] != pduAssociateRQ {
		t.Fatalf("PDU type = 0x%02x, want 0x01", rq[0])
	}
	// Bytes 2..6 are the BE length of everything after the 6-byte header.
	if got := int(rq[2])<<24 | int(rq[3])<<16 | int(rq[4])<<8 | int(rq[5]); got != len(rq)-6 {
		t.Fatalf("framed length %d, want %d", got, len(rq)-6)
	}
	if string(rq[10:26]) != "ANY-SCP         " {
		t.Fatalf("called AE not space-padded: %q", rq[10:26])
	}
}

// TestParseAssociateAC round-trips a synthetic AC through the acceptor parser,
// mirroring the fields the DCMTK lab server returns.
func TestParseAssociateAC(t *testing.T) {
	// presentation context AC: pcid, reserved, result=0 (accept), reserved, + transfer syntax
	pcAC := subItem(0x21, append([]byte{presentationContextID, 0x00, 0x00, 0x00},
		subItem(0x40, []byte(explicitVRLittleEnd))...))
	maxLen := []byte{0x00, 0x00, 0x40, 0x00} // 16384 BE
	ui := subItem(0x50, concat(
		subItem(0x51, maxLen),
		subItem(0x52, []byte("1.2.276.0.7230010.3.0.3.7.0")),
		subItem(0x55, []byte("OFFIS_DCMTK_370")),
	))
	body := append(make([]byte, 68), concat(pcAC, ui)...)

	res := &Results{}
	accepted, err := parseAssociateAC(body, res)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted {
		t.Fatal("expected context accepted")
	}
	if res.ImplementationClassUID != "1.2.276.0.7230010.3.0.3.7.0" {
		t.Fatalf("impl class UID = %q", res.ImplementationClassUID)
	}
	if res.ImplementationVersion != "OFFIS_DCMTK_370" {
		t.Fatalf("impl version = %q", res.ImplementationVersion)
	}
	if res.MaxPDULength != 16384 {
		t.Fatalf("max PDU = %d", res.MaxPDULength)
	}
	if res.AcceptedTransferSyntax != explicitVRLittleEnd {
		t.Fatalf("transfer syntax = %q", res.AcceptedTransferSyntax)
	}
}

// TestCEchoStatusRoundTrip encodes a C-ECHO command set and recovers a status
// element from an equivalently-encoded response.
func TestCEchoStatusRoundTrip(t *testing.T) {
	cmd := concat(
		dimseElement(tagCommandField, u16le(0x8030)), // C-ECHO-RSP
		dimseElement(tagStatus, u16le(0x0000)),       // success
	)
	status, err := findStatusElement(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if status != 0x0000 {
		t.Fatalf("status = 0x%04x, want 0x0000", status)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
