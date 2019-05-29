// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package keyfile_test

import (
	"testing"

	"bitbucket.org/creachadair/keyfile"
	"golang.org/x/xerrors"
)

func TestEmpty(t *testing.T) {
	f := keyfile.New("password")

	const slug = "anything"
	if f.Has(slug) {
		t.Errorf("Has(%q): got true, want false", slug)
	}
	if key, err := f.Get(slug); !xerrors.Is(err, keyfile.ErrNoSuchKey) {
		t.Errorf("Get(%q): got %v, %v, want %v", slug, key, err, keyfile.ErrNoSuchKey)
	}
	if f.Remove(slug) {
		t.Errorf("Remove(%q): got true, want false", slug)
	}
}
