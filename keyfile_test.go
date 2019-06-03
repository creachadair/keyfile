// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package keyfile_test

import (
	"bytes"
	"testing"

	"bitbucket.org/creachadair/keyfile"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/xerrors"
)

func TestEmpty(t *testing.T) {
	f := keyfile.New()

	const slug = "anything"
	if f.Has(slug) {
		t.Errorf("Has(%q): got true, want false", slug)
	}
	if key, err := f.Get(slug, "password"); !xerrors.Is(err, keyfile.ErrNoSuchKey) {
		t.Errorf("Get(%q): got %q, %v, want %v", slug, string(key), err, keyfile.ErrNoSuchKey)
	}
	if f.Remove(slug) {
		t.Errorf("Remove(%q): got true, want false", slug)
	}
}

func TestCloneProto(t *testing.T) {
	// Set up f1 with some random key material.
	f1 := keyfile.New()
	k1, err := f1.Random("foo", "whatever", 8)
	if err != nil {
		t.Fatalf("Random(8) failed: %v", err)
	}

	// Set up f2 as a clone of f1.
	f2 := keyfile.Clone(f1.Proto())

	// Remove foo from f1 and verify that it is gone.
	f1.Remove("foo")
	if got, err := f1.Get("foo", "whatever"); !xerrors.Is(err, keyfile.ErrNoSuchKey) {
		t.Errorf("f1.Get(foo): got (%q, %v), want (nil, %v)", string(got), err, keyfile.ErrNoSuchKey)
	}

	// Verify that f2 still has the key removed from f1.
	if got, err := f2.Get("foo", "whatever"); err != nil {
		t.Errorf("f2.Get(foo) failed: %v", err)
	} else if !bytes.Equal(got, k1) {
		t.Errorf("f2.Get(foo): got %q, want %q", string(got), string(k1))
	}

	// Verify that diddling the copy doesn't affect the original.
	p2 := f2.Proto()
	p2.Keys = nil // buh-bye

	if got, err := f2.Get("foo", "whatever"); err != nil {
		t.Errorf("f2.Get(foo) failed: %v", err)
	} else if !bytes.Equal(got, k1) {
		t.Errorf("f2.Get(foo): got %q, want %q", string(got), string(k1))
	}
}

func TestRoundTrip(t *testing.T) {
	var passphrase = "knucklebones"

	f := keyfile.New()
	get := func(slug, want string, werr error) {
		bits, err := f.Get(slug, passphrase)
		if got := string(bits); !xerrors.Is(err, werr) || got != want {
			t.Errorf("Get(%q): got (%q, %v), want (%q, %v)", slug, got, err, want, werr)
		}
	}
	set := func(slug, secret string) {
		if err := f.Set(slug, passphrase, []byte(secret)); err != nil {
			t.Errorf("Set(%q, %q): unexpected error: %v", slug, secret, err)
		}
	}

	rnd, err := f.Random("random", passphrase, 48)
	if err != nil {
		t.Fatalf("Random(48) failed: %v", err)
	} else if len(rnd) != 48 {
		t.Errorf("Random(48): got length %d, want 48", len(rnd))
	}

	get("email", "", keyfile.ErrNoSuchKey)
	get("random", string(rnd), nil)
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

	// Verify that key slugs come out in canonical order.
	wantSlugs := []string{"bank account", "email", "random", "website"}
	if diff := cmp.Diff(wantSlugs, f.Slugs()); diff != "" {
		t.Errorf("Wrong key slugs (-want, +got)\n%s", diff)
	}

	// Verify that we can write the bits out and read them back and still
	// recover the expected values.
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("Writing keyfile: %v", err)
	}
	if dec, err := keyfile.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Load failed: %v", err)
	} else {
		f = dec
	}

	get("email", "world is on fire", nil)
	get("bank account", "apoplexy1", nil)
	get("website", "cabbage tart", nil)
	get("random", string(rnd), nil)

	// Verify that serializing to JSON and back gives us back the same thing.
	var json bytes.Buffer
	if err := f.WriteJSON(&json); err != nil {
		t.Errorf("Writing JSON keyfile: %v", err)
	}
	t.Log("JSON:\n", json.String())

	cmp, err := keyfile.LoadJSON(&json)
	if err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}
	f = cmp

	get("email", "world is on fire", nil)
	get("bank account", "apoplexy1", nil)
	get("website", "cabbage tart", nil)
	get("random", string(rnd), nil)

	// Reload the encoded keyfile with the wrong passphrase and verify that we
	// get errors for each of the keys we request.
	if dec, err := keyfile.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Load failed: %v", err)
	} else {
		f = dec
	}

	passphrase = "fly you fools"
	get("email", "", keyfile.ErrBadPassphrase)
	get("bank account", "", keyfile.ErrBadPassphrase)
	get("website", "", keyfile.ErrBadPassphrase)
	get("random", "", keyfile.ErrBadPassphrase)
}
