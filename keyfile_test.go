// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package keyfile_test

import (
	crand "crypto/rand"
	"errors"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/creachadair/keyfile"
	"github.com/creachadair/mds/mtest"
	"github.com/google/go-cmp/cmp"
)

func TestEmpty(t *testing.T) {
	f := keyfile.New()
	key, err := f.Get("password")
	if !errors.Is(err, keyfile.ErrNoKey) {
		t.Errorf("Get (empty): got %q, %v, want %v", string(key), err, keyfile.ErrNoKey)
	}
}

func TestParseErrors(t *testing.T) {
	for _, test := range []string{
		"",                  // missing magic number
		"X",                 // invalid magic number
		"KF",                // "
		"KF\x00",            // incorrect version
		"KF\x01",            // "
		"KF\x02",            // short packet
		"KF\x02\x03\x00",    // truncated salt
		"KF\x02\x03\x02abc", // truncated nonce
	} {
		f, err := keyfile.Parse([]byte(test))
		if !errors.Is(err, keyfile.ErrBadPacket) {
			t.Errorf("Parse(%q): got %+v, %v; want %v", test, f, err, keyfile.ErrBadPacket)
		} else {
			t.Logf("Parse(%q): error OK: %v", test, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240427103817)))
	const passphrase = "send in the clanns"

	f := keyfile.New()
	rnd, err := f.Random(passphrase, 48)
	if err != nil {
		t.Fatalf("Random(48) failed: %v", err)
	} else if len(rnd) != 48 {
		t.Errorf("Random(48): got length %d, want 48", len(rnd))
	}
	if got, err := f.Get(passphrase); err != nil {
		t.Errorf("Get: got error %v, want %q", err, string(rnd))
	} else if diff := cmp.Diff(rnd, got); diff != "" {
		t.Errorf("Wrong key value (-want, +got):\n%s", diff)
	}

	const secret = "I have eaten the plums"
	if err := f.Set(passphrase, []byte(secret)); err != nil {
		t.Errorf("Set %q: unexpected error: %v", secret, err)
	}
	if got, err := f.Get(passphrase); err != nil {
		t.Errorf("Get: got error %v, want %q", err, secret)
	} else if diff := cmp.Diff([]byte(secret), got); diff != "" {
		t.Errorf("Wrong key value (-want, +got):\n%s", diff)
	}
}

func TestEncodeParse(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240427103823)))
	const (
		passphrase = "apoplexis"
		secret     = "rhubarb is disgusting"
	)

	f := keyfile.New()
	if err := f.Set(passphrase, []byte(secret)); err != nil {
		t.Fatalf("Set %q: unexpected error: %v", secret, err)
	}

	// Verify that we can round-trip the encoded packet.
	enc := f.Encode()
	dec, err := keyfile.Parse(enc)
	if err != nil {
		t.Fatalf("Parsing keyfile: %v", err)
	}

	opt := cmp.AllowUnexported(keyfile.File{})
	if diff := cmp.Diff(f, dec, opt); diff != "" {
		t.Errorf("Keyfile mismatch (-want, +got):\n%s", diff)
	}

	if got, err := dec.Get(passphrase); err != nil {
		t.Errorf("Get: got error %v, want %q", err, secret)
	} else if diff := cmp.Diff([]byte(secret), got); diff != "" {
		t.Errorf("Wrong key value (-want, +got):\n%s", diff)
	}
}

func TestSet(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240427103839)))
	const secret = "key"

	f := keyfile.New()
	if err := f.Set("whatever", []byte(secret)); err != nil {
		t.Errorf("Set %q: unexpected error: %v", secret, err)
	}
	if got, err := f.Get("wrong"); err == nil {
		t.Errorf("Get with wrong passphrase: got %q, %v want error", string(got), err)
	}
	if key, err := f.Get("whatever"); err != nil {
		t.Errorf("Get failed: %v", err)
	} else if got := string(key); got != secret {
		t.Errorf("Get: got %q, want %q", got, secret)
	}
}
