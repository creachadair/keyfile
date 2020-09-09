// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package keyfile provides an interface to read and write secret keys in a
// persistent format protected by a passphrase.
//
// Each secret is stored in a keypb.Keyfile protocol buffer message, inside
// which the secret is encrypted with AES-256 in CTR mode. The encryption key
// is derived from a user passphrase using the scrypt algorithm.
package keyfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"

	"github.com/creachadair/keyfile/keypb"
	"golang.org/x/crypto/scrypt"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrBadPassphrase is reported when a passphrase decrypt a key.
	ErrBadPassphrase = errors.New("invalid passphrase")

	// ErrNoKey is reported by Get when the keyfile has no key.
	ErrNoKey = errors.New("no key is present")
)

const (
	aesKeyBytes  = 32 // for AES-256
	keySaltBytes = 16 // size of random salt for scrypt
)

// A File represents a keyfile.
type File struct {
	*keypb.Keyfile
}

// New creates a new empty keyfile.
func New() *File { return &File{Keyfile: new(keypb.Keyfile)} }

// Load loads a wire-format Keyfile protobuf message from r
func Load(r io.Reader) (*File, error) {
	bits, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	kf := new(keypb.Keyfile)
	if err := proto.Unmarshal(bits, kf); err != nil {
		return nil, err
	}
	return &File{Keyfile: kf}, nil
}

// Get decrypts and returns the key from f using the given passphrase.
// It returns ErrBadPassphrase if the key cannot be decrypted.
// It returns ErrNoKey if f is empty.
func (f *File) Get(passphrase string) ([]byte, error) {
	if f.Key == nil || len(f.Key.Data) == 0 {
		return nil, ErrNoKey
	}

	// Decrypt the key wrapper.
	ctr, err := keyCipher(passphrase, f.Key)
	if err != nil {
		return nil, fmt.Errorf("keyfile decrypt: %w", err)
	}
	tmp := make([]byte, len(f.Key.Data))
	ctr.XORKeyStream(tmp, f.Key.Data)

	// Decode and return the secret. If this fails, report that the passphrase
	// was invalid.
	sec, err := checkKey(tmp)
	if err != nil {
		return nil, fmt.Errorf("keyfile verify: %w", err)
	}
	return sec, nil
}

// Random generates a random secret with the given length, encrypts it with the
// passphrase, and stores it in f, replacing any previous data. The generated
// secret is returned. It is an error if nbytes <= 0.
func (f *File) Random(passphrase string, nbytes int) ([]byte, error) {
	if nbytes <= 0 {
		return nil, errors.New("invalid secret size (must be positive)")
	}
	secret := make([]byte, nbytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := f.Set(passphrase, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Set encrypts the secret with the passphrase and stores it in f, replacing
// any previous data.
func (f *File) Set(passphrase string, secret []byte) error {
	key := new(keypb.Keyfile_Key)
	ctr, err := keyCipher(passphrase, key)
	if err != nil {
		return fmt.Errorf("keyfile encrypt: %w", err)
	}

	// Package and encrypt the secret.
	pkg := make([]byte, len(secret)+4) // +4 for checksum
	copy(pkg[4:], secret)
	binary.BigEndian.PutUint32(pkg, crc32.ChecksumIEEE(secret))
	ctr.XORKeyStream(pkg, pkg)
	key.Data = pkg
	f.Key = key
	return nil
}

// WriteTo encodes f to the specified w in protobuf wire format.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	bits, err := proto.Marshal(f.Keyfile)
	if err != nil {
		return 0, err
	}
	nw, err := w.Write(bits)
	return int64(nw), err
}

// keySalt returns the passphrase key salt, creating it if necessary.  This can
// only fail if random generation fails.
func keySalt(key *keypb.Keyfile_Key) ([]byte, error) {
	if len(key.Salt) == 0 {
		var buf [keySaltBytes]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		key.Salt = buf[:]
	}
	return key.Salt, nil
}

// keyIV returns the key's initialization vector, creating it if necessary.
func keyIV(key *keypb.Keyfile_Key) ([]byte, error) {
	if len(key.Init) == 0 {
		key.Init = make([]byte, aes.BlockSize)
		if _, err := rand.Read(key.Init); err != nil {
			return nil, err
		}
	}
	return key.Init, nil
}

// keyCipher returns an CTR mode stream for the specified key and passphrase.
func keyCipher(passphrase string, key *keypb.Keyfile_Key) (cipher.Stream, error) {
	salt, err := keySalt(key)
	if err != nil {
		return nil, fmt.Errorf("key salt: %w", err)
	}
	ckey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, aesKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}

	iv, err := keyIV(key)
	if err != nil {
		return nil, fmt.Errorf("initialization vector: %w", err)
	}
	blk, err := aes.NewCipher(ckey)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(blk, iv), nil
}

// checkKey decodes a decrypted key wrapper and performs sanity checks.  On
// success it returns the payload; otherwise ErrBadPassphrase.
func checkKey(data []byte) ([]byte, error) {
	got := binary.BigEndian.Uint32(data)
	want := crc32.ChecksumIEEE(data[4:])
	if got != want {
		return nil, ErrBadPassphrase
	}
	return data[4:], nil
}
