// Copyright (c) 2026 The mailfrom-milter Authors. All rights reserved.
// Use of this source code is governed by a GNU GPLv3 style
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"testing"

	"github.com/emersion/go-milter"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// startTestServer spins up a milter server on a random port and returns the
// address together with a cleanup function.
func startTestServer(t *testing.T, action string) string {
	t.Helper()

	cfg = loadConfig()
	cfg.action = action
	cfg.rejectCode = "421"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &milter.Server{
		NewMilter: func() milter.Milter {
			return &milterSession{}
		},
		Actions: milter.OptAddHeader,
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})

	return ln.Addr().String()
}

// sendMessage drives a full milter conversation and returns the final action
// from End() (Body), plus modify actions (header additions, etc.).
//
// authUser — empty string means unauthenticated session.
func sendMessage(t *testing.T, addr, authUser, envelopeFrom, fromHeader string) ([]milter.ModifyAction, *milter.Action) {
	t.Helper()

	c := milter.NewClientWithOptions("tcp", addr, milter.ClientOptions{
		ActionMask: milter.OptAddHeader,
	})
	sess, err := c.Session()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	// CONNECT macros + Conn
	if err := sess.Macros(milter.CodeConn, "{client_addr}", "127.0.0.1"); err != nil {
		t.Fatalf("macros conn: %v", err)
	}
	if act, err := sess.Conn("localhost", milter.FamilyInet, 25, "127.0.0.1"); err != nil {
		t.Fatalf("conn: %v", err)
	} else if act.Code != milter.ActContinue {
		t.Fatalf("conn action: %v", act.Code)
	}

	// HELO
	if act, err := sess.Helo("localhost"); err != nil {
		t.Fatalf("helo: %v", err)
	} else if act.Code != milter.ActContinue {
		t.Fatalf("helo action: %v", act.Code)
	}

	// MAIL FROM macros + Mail
	if err := sess.Macros(milter.CodeMail, "{auth_authen}", authUser, "{mail_addr}", envelopeFrom); err != nil {
		t.Fatalf("macros mail: %v", err)
	}
	mailAct, err := sess.Mail(envelopeFrom, nil)
	if err != nil {
		t.Fatalf("mail: %v", err)
	}
	// If the milter already rejected/accepted at MAIL FROM stage, return early.
	if mailAct.Code != milter.ActContinue {
		return nil, mailAct
	}

	// RCPT TO
	if act, err := sess.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("rcpt: %v", err)
	} else if act.Code != milter.ActContinue {
		t.Fatalf("rcpt action: %v", act.Code)
	}

	// Headers
	if act, err := sess.HeaderField("From", fromHeader); err != nil {
		t.Fatalf("header field: %v", err)
	} else if act.Code != milter.ActContinue {
		t.Fatalf("header field action: %v", act.Code)
	}
	eohAct, err := sess.HeaderEnd()
	if err != nil {
		t.Fatalf("header end: %v", err)
	}
	// Milter may reject at EOH (Headers callback).
	if eohAct.Code != milter.ActContinue {
		return nil, eohAct
	}

	// Body (EOB)
	modifyActs, finalAct, err := sess.End()
	if err != nil {
		t.Fatalf("end: %v", err)
	}
	return modifyActs, finalAct
}

// ---------------------------------------------------------------------------
// Integration tests — action: reject
// ---------------------------------------------------------------------------

func TestIntegration_Reject_Unauthenticated(t *testing.T) {
	addr := startTestServer(t, actionReject)
	_, act := sendMessage(t, addr, "", "user@example.com", "User <user@example.com>")
	// Unauthenticated sessions are accepted immediately at MAIL FROM.
	if act.Code != milter.ActAccept {
		t.Errorf("unauthenticated: got %v, want Accept", act.Code)
	}
}

func TestIntegration_Reject_AuthAndFromMatch(t *testing.T) {
	addr := startTestServer(t, actionReject)
	_, act := sendMessage(t, addr, "user@example.com", "user@example.com", "User <user@example.com>")
	if act.Code != milter.ActAccept {
		t.Errorf("matching domains: got %v, want Accept", act.Code)
	}
}

func TestIntegration_Reject_SpoofedFromHeader(t *testing.T) {
	addr := startTestServer(t, actionReject)
	_, act := sendMessage(t, addr, "attacker@attacker.com", "attacker@attacker.com", "CEO <ceo@victim.com>")
	if act.Code != milter.ActReplyCode {
		t.Errorf("spoofed From: got %v, want ReplyCode", act.Code)
	}
	if act.SMTPCode != 421 {
		t.Errorf("spoofed From: SMTP code %d, want 421", act.SMTPCode)
	}
}

func TestIntegration_Reject_AuthUserMismatch(t *testing.T) {
	// authUser domain ≠ envelopeFrom domain → reject at MAIL FROM
	addr := startTestServer(t, actionReject)
	_, act := sendMessage(t, addr, "user@legit.com", "sender@other.com", "sender@other.com")
	if act.Code != milter.ActReplyCode {
		t.Errorf("auth mismatch: got %v, want ReplyCode", act.Code)
	}
	if act.SMTPCode != 421 {
		t.Errorf("auth mismatch: SMTP code %d, want 421", act.SMTPCode)
	}
}

func TestIntegration_Reject_RejectCode550(t *testing.T) {
	addr := startTestServer(t, actionReject)
	cfg.rejectCode = "550"
	_, act := sendMessage(t, addr, "attacker@attacker.com", "attacker@attacker.com", "CEO <ceo@victim.com>")
	if act.Code != milter.ActReplyCode {
		t.Errorf("550 reject: got %v, want ReplyCode", act.Code)
	}
	if act.SMTPCode != 550 {
		t.Errorf("550 reject: SMTP code %d, want 550", act.SMTPCode)
	}
}

// ---------------------------------------------------------------------------
// Integration tests — action: discard
// ---------------------------------------------------------------------------

func TestIntegration_Discard_SpoofedFromHeader(t *testing.T) {
	addr := startTestServer(t, actionDiscard)
	_, act := sendMessage(t, addr, "attacker@attacker.com", "attacker@attacker.com", "CEO <ceo@victim.com>")
	if act.Code != milter.ActDiscard {
		t.Errorf("discard spoofed: got %v, want Discard", act.Code)
	}
}

func TestIntegration_Discard_ValidMessage(t *testing.T) {
	addr := startTestServer(t, actionDiscard)
	_, act := sendMessage(t, addr, "user@example.com", "user@example.com", "user@example.com")
	if act.Code != milter.ActAccept {
		t.Errorf("discard valid: got %v, want Accept", act.Code)
	}
}

// ---------------------------------------------------------------------------
// Integration tests — action: quarantine_header
// ---------------------------------------------------------------------------

func TestIntegration_Quarantine_SpoofedFromHeader(t *testing.T) {
	addr := startTestServer(t, actionQuarantineHeader)
	modifyActs, act := sendMessage(t, addr, "attacker@attacker.com", "attacker@attacker.com", "CEO <ceo@victim.com>")
	if act.Code != milter.ActAccept {
		t.Errorf("quarantine spoofed: final action %v, want Accept", act.Code)
	}
	assertHeader(t, modifyActs, headerQuarantine, "yes")
	assertHeader(t, modifyActs, headerEnvelopeFrom, "attacker@attacker.com")
}

func TestIntegration_Quarantine_ValidMessage(t *testing.T) {
	addr := startTestServer(t, actionQuarantineHeader)
	modifyActs, act := sendMessage(t, addr, "user@example.com", "user@example.com", "User <user@example.com>")
	if act.Code != milter.ActAccept {
		t.Errorf("quarantine valid: final action %v, want Accept", act.Code)
	}
	assertHeader(t, modifyActs, headerQuarantine, "no")
}

// ---------------------------------------------------------------------------
// Integration tests — action: accept
// ---------------------------------------------------------------------------

func TestIntegration_Accept_SpoofedFromHeader(t *testing.T) {
	addr := startTestServer(t, actionDunno)
	_, act := sendMessage(t, addr, "attacker@attacker.com", "attacker@attacker.com", "CEO <ceo@victim.com>")
	if act.Code != milter.ActAccept {
		t.Errorf("accept spoofed: got %v, want Accept", act.Code)
	}
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertHeader(t *testing.T, acts []milter.ModifyAction, name, wantValue string) {
	t.Helper()
	for _, a := range acts {
		if a.HeaderName == name {
			if a.HeaderValue != wantValue {
				t.Errorf("header %q = %q, want %q", name, a.HeaderValue, wantValue)
			}
			return
		}
	}
	t.Errorf("header %q not found in modify actions", name)
}
