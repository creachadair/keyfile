// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package keyfile provides an interface to read and write encryption keys and
// other secrets in a persistent format protected by a passphrase.
package keyfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"sort"

	"bitbucket.org/creachadair/keyfile/keypb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/snappy"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/xerrors"
)

var (
	// ErrNoSuchKey is reported when requesting an unknown key slug.
	ErrNoSuchKey = xerrors.New("no matching key")

	// ErrBadPassphrase is reported when a passphrase decrypt a key.
	ErrBadPassphrase = xerrors.New("invalid passphrase")
)

const aesKeyBytes = 32 // for AES-256

// A File represents a collection of keys.
type File struct {
	pb         *keypb.Keyfile
	passphrase string
}

// New creates a new empty file encrypted with the specified passphrase.
func New(passphrase string) *File {
	return &File{pb: new(keypb.Keyfile), passphrase: passphrase}
}

// Load loads a file encrypted with the given passphrase from r.
func Load(r io.Reader, passphrase string) (*File, error) {
	bits, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	kf := new(keypb.Keyfile)
	if err := proto.Unmarshal(bits, kf); err != nil {
		return nil, err
	}
	sort.Slice(kf.Keys, func(i, j int) bool {
		return kf.Keys[i].Slug < kf.Keys[j].Slug
	})
	return &File{pb: kf, passphrase: passphrase}, nil
}

// Slugs returns a slice of the key slugs known to f.
func (f *File) Slugs() []string {
	var slugs []string
	for _, key := range f.pb.Keys {
		slugs = append(slugs, key.Slug)
	}
	return slugs
}

// Has reports whether f contains a key with the specified slug.
func (f *File) Has(slug string) bool { return f.findKey(slug) != nil }

// Get decrypts and returns the key with the specified slug.
// It reports ErrNoSuchKey if no such key exists in f.
// It reports ErrBadPassphrase if they key cannot be decrypted.
func (f *File) Get(slug string) ([]byte, error) {
	key := f.findKey(slug)
	if key == nil {
		return nil, xerrors.Errorf("get %q: %w", slug, ErrNoSuchKey)
	}

	// Decrypt and decompress the key material.
	ctr, err := f.fileCipher(aesKeyBytes, key.Init)
	if err != nil {
		return nil, xerrors.Errorf("get %q decrypt: %w", slug, err)
	}
	tmp := make([]byte, len(key.Data))
	ctr.XORKeyStream(tmp, key.Data)
	dec, err := snappy.Decode(nil, tmp)
	if err != nil {
		return nil, xerrors.Errorf("get %q: %w", slug, ErrBadPassphrase)
	}

	// Decode and return the secret.
	var sec keypb.Keyfile_Secret
	if err := proto.Unmarshal(dec, &sec); err != nil {
		return nil, xerrors.Errorf("get %q: %w", slug, err)
	}
	return sec.Secret, nil
}

// Set stores the specified secret under the given slug. If the slug already
// exists, its contents are replaced; otherwise, a new key is added.
func (f *File) Set(slug string, secret []byte) error {
	key := f.findKey(slug)
	if key == nil {
		// Create a new entry and stuff it into the collection.
		key = &keypb.Keyfile_Key{Slug: slug}
		f.pb.Keys = append(f.pb.Keys, key)
	}

	// Populate a fresh initialization vector for this key.
	key.Init = make([]byte, aes.BlockSize)
	if _, err := rand.Read(key.Init); err != nil {
		return xerrors.Errorf("set %q: %w", slug, err)
	}
	ctr, err := f.fileCipher(aesKeyBytes, key.Init)
	if err != nil {
		return xerrors.Errorf("set %q encrypt: %w", slug, err)
	}

	// Package, compress, and encrypt the secret.
	bits, err := proto.Marshal(&keypb.Keyfile_Secret{
		Secret: secret,
	})
	if err != nil {
		return xerrors.Errorf("set %q: %w", slug, err)
	}
	key.Data = snappy.Encode(nil, bits)
	ctr.XORKeyStream(key.Data, key.Data)

	return nil
}

// Remove removes the key associated with the given slug if it is present, and
// reports whether anything was removed.
func (f *File) Remove(slug string) bool {
	for i, key := range f.pb.Keys {
		if key.Slug == slug {
			f.pb.Keys = append(f.pb.Keys[:i], f.pb.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// WriteTo encodes f to the specified w.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	sort.Slice(f.pb.Keys, func(i, j int) bool {
		return f.pb.Keys[i].Slug < f.pb.Keys[j].Slug
	})
	bits, err := proto.Marshal(f.pb)
	if err != nil {
		return 0, err
	}
	nw, err := w.Write(bits)
	return int64(nw), err
}

// findKey returns the first key with the specified slug, or nil.
func (f *File) findKey(slug string) *keypb.Keyfile_Key {
	for _, key := range f.pb.Keys {
		if key.Slug == slug {
			return key
		}
	}
	return nil
}

// keySalt returns the passphrase key salt, creating it if necessary.
func (f *File) keySalt() ([]byte, error) {
	if len(f.pb.KeySalt) == 0 {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		f.pb.KeySalt = buf[:]
	}
	return f.pb.KeySalt, nil
}

// fileKey returns an n-byte encryption key derived from the passphase.
func (f *File) fileKey(n int) ([]byte, error) {
	salt, err := f.keySalt()
	if err != nil {
		return nil, xerrors.Errorf("key salt: %w", err)
	}
	key, err := scrypt.Key([]byte(f.passphrase), salt, 32768, 8, 1, n)
	if err != nil {
		return nil, xerrors.Errorf("scrypt: %w", err)
	}
	return key, nil
}

// fileCipher returns an CTR mode stream using the file's key.
func (f *File) fileCipher(n int, iv []byte) (cipher.Stream, error) {
	key, err := f.fileKey(n)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(blk, iv), nil
}
