// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package keyfile_test

import (
	"errors"
	"testing"

	"github.com/creachadair/keyfile"
	"github.com/google/go-cmp/cmp"
)

func TestEmpty(t *testing.T) {
	f := keyfile.New()
	key, err := f.Get("password")
	if !errors.Is(err, keyfile.ErrNoKey) {
		t.Errorf("Get (empty): got %q, %v, want %v", string(key), err, keyfile.ErrNoKey)
	}
}

func TestRoundTrip(t *testing.T) {
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
	const (
		passphrase = "apoplexis"
		secret     = "rhubarb is disgusting"
	)

	f := keyfile.New()
	if err := f.Set(passphrase, []byte(secret)); err != nil {
		t.Fatalf("Set %q: unexpected error: %v", secret, err)
	}

	// Verify that we can round-trip the encoded packet.
	enc, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("Encoding keyfile: %v", err)
	}

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
