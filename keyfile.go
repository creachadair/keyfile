// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package keyfile provides an interface to read and write small secrets such
// as encryption keys in a persistent format protected by a passphrase.
//
// Each secret is stored in a binary packet, inside which the secret is
// encrypted and authenticated with AES-256 in Galois Counter Mode (GCM). The
// encryption key is derived from a user passphrase using the scrypt algorithm.
//
// The binary packet is structured as follows:
//
//   Pos          Len     Description
//   0            3       Format tag, "KF\x02" == "\x4b\x46\x02"
//   3            1       Length of key generation salt in bytes (slen)
//   4            1       Length of GCM nonce in bytes (nlen)
//   5            slen    Key generation salt
//   5+slen       nlen    GCM nonce
//   5+slen+nlen  dlen    The encrypted data packet (to end)
//
// The data packet is encrypteed with AES-256 in GCM.
//
package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/scrypt"
)

var (
	// ErrBadPassphrase is reported when a passphrase decrypt a key.
	ErrBadPassphrase = errors.New("invalid passphrase")

	// ErrNoKey is reported by Get when the keyfile has no key.
	ErrNoKey = errors.New("no key is present")

	// ErrBadPacket is reported when parsing an invalid keyfile packet.
	ErrBadPacket = errors.New("parse: bad packet")
)

const (
	aesKeyBytes      = 32 // for AES-256
	keySaltBytes     = 16 // size of random salt for scrypt
	scryptWorkFactor = 1 << 15

	magic = "KF\x02" // format magic number
)

// A File represents a keyfile. A zero value is ready for use.
type File struct {
	salt  []byte // key-generation salt
	nonce []byte // AEAD nonce
	data  []byte // encrypted data packet
}

// New creates a new empty *File.
func New() *File { return new(File) }

// Parse parses a binary keyfile packet into a *File.
func Parse(data []byte) (*File, error) {
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, fmt.Errorf("%w: invalid magic", ErrBadPacket)
	}
	data = data[len(magic):]
	if len(data) < 2 { // slen, nlen
		return nil, fmt.Errorf("%w: truncated packet", ErrBadPacket)
	}
	slen := int(data[0])
	if 2+slen > len(data) {
		return nil, fmt.Errorf("%w: invalid salt", ErrBadPacket)
	}
	nlen := int(data[1])
	if 2+nlen+nlen > len(data) {
		return nil, fmt.Errorf("%w: invalid nonce", ErrBadPacket)
	}
	user := data[2+slen+nlen:]
	return &File{
		salt:  data[2 : 2+slen],
		nonce: data[2+slen : 2+slen+nlen],
		data:  user,
	}, nil
}

// Encode encodes f in binary format for storage, such that
// keyfile.Parse(f.Encode()) is equivalent to f.
func (f *File) Encode() []byte {
	slen, nlen := len(f.salt), len(f.nonce)
	buf := make([]byte, len(magic)+2+slen+nlen+len(f.data))
	n := copy(buf, []byte(magic))
	buf[n] = byte(slen)
	buf[n+1] = byte(nlen)
	copy(buf[n+2:], f.salt)
	copy(buf[n+2+slen:], f.nonce)
	copy(buf[n+2+slen+nlen:], f.data)
	return buf
}

// Get decrypts and returns the key from f using the given passphrase.
// It returns ErrBadPassphrase if the key cannot be decrypted.
// It returns ErrNoKey if f is empty.
func (f *File) Get(passphrase string) ([]byte, error) {
	if len(f.salt) == 0 || len(f.nonce) == 0 {
		return nil, ErrNoKey
	}

	// Decrypt the key wrapper.
	aead, err := f.keyCipher(passphrase)
	if err != nil {
		return nil, fmt.Errorf("keyfile init: %w", err)
	}
	dec, err := aead.Open(nil, f.nonce, f.data, nil)
	if err != nil {
		return nil, fmt.Errorf("keyfile verify: %w", err)
	}
	return dec, nil
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
	*f = File{} // reset
	aead, err := f.keyCipher(passphrase)
	if err != nil {
		return fmt.Errorf("keyfile init: %w", err)
	}
	f.nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(f.nonce); err != nil {
		return err
	}
	f.data = aead.Seal(nil, f.nonce, secret, nil)
	return nil
}

// keySalt returns the passphrase key salt, creating it if necessary.  This can
// only fail if random generation fails.
func (f *File) keySalt() ([]byte, error) {
	if len(f.salt) == 0 {
		var buf [keySaltBytes]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		f.salt = buf[:]
	}
	return f.salt, nil
}

// keyCipher returns a cipher.AEAD for f using the given passphrase.
func (f *File) keyCipher(passphrase string) (cipher.AEAD, error) {
	salt, err := f.keySalt()
	if err != nil {
		return nil, fmt.Errorf("key salt: %w", err)
	}
	ckey, err := scrypt.Key([]byte(passphrase), salt, scryptWorkFactor, 8, 1, aesKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	blk, err := aes.NewCipher(ckey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// LoadKey is a convenience function to load and decrypt the contents of a key
// from a stored binary-format keyfile. The pf function is called to obtain a
// passphrase.
func LoadKey(path string, pf func() (string, error)) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kf, err := Parse(data)
	if err != nil {
		return nil, err
	}
	passphrase, err := pf()
	if err != nil {
		return nil, err
	}
	return kf.Get(passphrase)
}
