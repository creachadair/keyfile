// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package keyfile_test

import (
	"bytes"
	"testing"

	"bitbucket.org/creachadair/keyfile"
	"bitbucket.org/creachadair/keyfile/keypb"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/xerrors"
)

func TestEmpty(t *testing.T) {
	f := keyfile.New("password")

	const slug = "anything"
	if f.Has(slug) {
		t.Errorf("Has(%q): got true, want false", slug)
	}
	if key, err := f.Get(slug); !xerrors.Is(err, keyfile.ErrNoSuchKey) {
		t.Errorf("Get(%q): got %q, %v, want %v", slug, string(key), err, keyfile.ErrNoSuchKey)
	}
	if f.Remove(slug) {
		t.Errorf("Remove(%q): got true, want false", slug)
	}
}

func TestRoundTrip(t *testing.T) {
	f := keyfile.New("password")
	get := func(slug, want string, werr error) {
		bits, err := f.Get(slug)
		if got := string(bits); !xerrors.Is(err, werr) || got != want {
			t.Errorf("Get(%q): got (%q, %v), want (%q, %v)", slug, got, err, want, werr)
		}
	}
	set := func(slug, secret string) {
		if err := f.Set(slug, []byte(secret)); err != nil {
			t.Errorf("Set(%q, %q): unexpected error: %v", slug, secret, err)
		}
	}

	get("email", "", keyfile.ErrNoSuchKey)
	set("email", "carebears")
	set("website", "dogfart")

	get("email", "carebears", nil)
	f.Remove("email")
	get("email", "", keyfile.ErrNoSuchKey)

	get("website", "dogfart", nil)
	set("website", "cabbage tart")
	get("website", "cabbage tart", nil)

	set("email", "world is on fire")
	set("bank account", "apoplexy1")

	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("Writing keyfile: %v", err)
	}

	var kf keypb.Keyfile
	if err := proto.Unmarshal(buf.Bytes(), &kf); err != nil {
		t.Fatalf("Decoding keyfile: %v", err)
	}

	// Verify that key slugs come out in canonical order.
	wantSlugs := []string{"bank account", "email", "website"}
	if diff := cmp.Diff(wantSlugs, f.Slugs()); diff != "" {
		t.Errorf("Wrong key slugs (-want, +got)\n%s", diff)
	}

	// Reload the encoded keyfile and check the outputs.
	if dec, err := keyfile.Load(bytes.NewReader(buf.Bytes()), "password"); err != nil {
		t.Fatalf("Load failed: %v", err)
	} else {
		f = dec
	}

	get("email", "world is on fire", nil)
	get("bank account", "apoplexy1", nil)
	get("website", "cabbage tart", nil)

	// Reload the encoded keyfile with the wrong passphrase and verify that we
	// get errors.
	if dec, err := keyfile.Load(bytes.NewReader(buf.Bytes()), "wrong"); err != nil {
		t.Fatalf("Load failed: %v", err)
	} else {
		f = dec
	}

	get("email", "", keyfile.ErrBadPassphrase)
	get("bank account", "", keyfile.ErrBadPassphrase)
	get("website", "", keyfile.ErrBadPassphrase)
}
