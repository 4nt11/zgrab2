package mllp

import (
	"net"
	"testing"
)

// TestTier2Framing: a peer that returns an empty MLLP frame (<SB><EB><CR>) — as a
// misconfigured Mirth does — must be detected via framing, not dropped for lacking MSH.
func TestTier2Framing(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 512)
		_, _ = server.Read(buf)              // consume the probe
		_, _ = server.Write([]byte{sb, eb, cr}) // reply: empty MLLP frame
		_ = server.Close()
	}()
	res, err := Probe(client, "QBP^Q11")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Detected || res.DetectionMethod != "mllp-frame" {
		t.Fatalf("want detected via mllp-frame, got detected=%v method=%q", res.Detected, res.DetectionMethod)
	}
}

// TestTier3NonMLLP: a peer that sends non-framed garbage must NOT be detected.
func TestTier3NonMLLP(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
		_ = server.Close()
	}()
	res, err := Probe(client, "QBP^Q11")
	if err == nil && res.Detected {
		t.Fatalf("non-MLLP peer should not be detected, got %+v", res)
	}
}

// TestFrame checks the MLLP <SB>payload<EB><CR> envelope.
func TestFrame(t *testing.T) {
	got := frame("MSH|x")
	if got[0] != sb {
		t.Fatalf("missing SB, got 0x%02x", got[0])
	}
	if got[len(got)-2] != eb || got[len(got)-1] != cr {
		t.Fatalf("bad trailer: % x", got[len(got)-2:])
	}
	if string(got[1:len(got)-2]) != "MSH|x" {
		t.Fatalf("payload corrupted: %q", got[1:len(got)-2])
	}
}

// TestStripFraming tolerates a leading SB and trailing EB/CR.
func TestStripFraming(t *testing.T) {
	in := append([]byte{sb}, append([]byte("MSH|abc"), eb, cr)...)
	if got := string(stripFraming(in)); got != "MSH|abc" {
		t.Fatalf("stripFraming = %q, want %q", got, "MSH|abc")
	}
}

// TestParseHL7 parses the actual ACK the lab engine returned, confirming the
// MSH fingerprint fields and the MSA acknowledgement code/text.
func TestParseHL7(t *testing.T) {
	ack := "MSH|^~\\&|CSEF_ENGINE|CLINICA|SENDER|CLINICA|20260702024706||ACK|ACK20260702024706|P|2.5\r" +
		"MSA|AR|ZGRAB220260702024706|rejected: UnsupportedMessageType"
	res := &Results{}
	if !parseHL7(ack, res) {
		t.Fatal("expected MSH to be found")
	}
	checks := map[string]struct{ got, want string }{
		"sending_application": {res.SendingApplication, "CSEF_ENGINE"},
		"sending_facility":    {res.SendingFacility, "CLINICA"},
		"message_type":        {res.MessageType, "ACK"},
		"version":             {res.Version, "2.5"},
		"ack_code":            {res.AckCode, "AR"},
		"ack_text":            {res.AckText, "rejected: UnsupportedMessageType"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
}

// TestParseERR pulls the user message out of ERR-8, and MSH-11 processing ID.
func TestParseERR(t *testing.T) {
	msg := "MSH|^~\\&|MIRTH|HOSPITAL|ZGRAB2|ZGRAB2|20260702||ACK|12345|T|2.5.1\r" +
		"MSA|AE|12345|unsupported\r" +
		"ERR|||207|E||||Unknown message type ZZZ^Z99"
	res := &Results{}
	if !parseHL7(msg, res) {
		t.Fatal("expected MSH found")
	}
	if res.ProcessingID != "T" {
		t.Errorf("processing_id = %q, want T", res.ProcessingID)
	}
	if res.ErrText != "Unknown message type ZZZ^Z99" {
		t.Errorf("err_text = %q", res.ErrText)
	}
}

// TestParseHL7NonHL7 rejects a response with no MSH segment.
func TestParseHL7NonHL7(t *testing.T) {
	if parseHL7("garbage\rmore garbage", &Results{}) {
		t.Fatal("expected non-HL7 payload to be rejected")
	}
}
