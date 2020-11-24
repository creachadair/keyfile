// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package keyfile provides an interface to read and write small secrets such
// as encryption keys in a persistent format protected by a passphrase.
//
// Each secret is stored in a binary packet, inside which the secret is
// encrypted with AES-256 in CTR mode. The encryption key is derived from a
// user passphrase using the scrypt algorithm.
//
// The binary packet is structured as follows:
//
//   Pos         Len     Description
//   0           3       Format tag, "KF\x01" == "\x4b\x46\x01"
//   3           1       Length of initialization vector in bytes (ilen)
//   4           1       Length of key generation salt in bytes (slen)
//   5           ilen    Initialization vector
//   5+ilen      slen    Key generation salt
//   5+ilen+slen 4+dlen  The encrypted data packet (see below)
//
// The data packet is encrypted with AES-256 in CTR mode. The plaintext
// packet for user data of dlen bytes has this format:
//
//   Pos    Len   Description
//   0      4     IEEE CRC32 of (init + salt + userData); network byte order
//   4      dlen  User data
//
// Thus, the minimum syntactically valid file is 9 bytes in length, with
// ilen = slen = dlen = 0, the format tag, and the 4-byte CRC.
//
package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
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
	aesKeyBytes  = 32 // for AES-256
	keySaltBytes = 16 // size of random salt for scrypt

	magic = "KF\x01" // format magic number
)

// A File represents a keyfile. A zero value is ready for use.
type File struct {
	init []byte // initialization vector
	salt []byte // key-generation salt
	data []byte // encrypted data packet
}

// New creates a new empty *File.
func New() *File { return new(File) }

// Parse parses a binary keyfile packet into a *File.
func Parse(data []byte) (*File, error) {
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, fmt.Errorf("%w: invalid magic", ErrBadPacket)
	}
	data = data[len(magic):]
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: truncated packet", ErrBadPacket)
	}
	ilen := int(data[0])
	if 2+ilen > len(data) {
		return nil, fmt.Errorf("%w: invalid IV", ErrBadPacket)
	}
	slen := int(data[1])
	if 2+ilen+slen > len(data) {
		return nil, fmt.Errorf("%w: invalid salt", ErrBadPacket)
	}
	user := data[2+ilen+slen:]
	if len(user) < 4 {
		return nil, fmt.Errorf("%w: invalid CRC", ErrBadPacket)
	}
	return &File{
		init: data[2 : 2+ilen],
		salt: data[2+ilen : 2+ilen+slen],
		data: user,
	}, nil
}

// Encode encodes f in binary format for storage, such that
// keyfile.Parse(f.Encode()) is equivalent to f.
func (f *File) Encode() []byte {
	ilen, slen := len(f.init), len(f.salt)
	buf := make([]byte, len(magic)+ilen+slen+len(f.data)+2)
	n := copy(buf, []byte(magic))
	buf[n] = byte(ilen)
	buf[n+1] = byte(slen)
	copy(buf[n+2:], f.init)
	copy(buf[n+2+ilen:], f.salt)
	copy(buf[n+2+ilen+slen:], f.data)
	return buf
}

// Get decrypts and returns the key from f using the given passphrase.
// It returns ErrBadPassphrase if the key cannot be decrypted.
// It returns ErrNoKey if f is empty.
func (f *File) Get(passphrase string) ([]byte, error) {
	if len(f.init) == 0 || len(f.salt) == 0 || len(f.data) <= 4 {
		return nil, ErrNoKey
	}

	// Decrypt the key wrapper.
	ctr, err := f.keyCipher(passphrase)
	if err != nil {
		return nil, fmt.Errorf("keyfile decrypt: %w", err)
	}
	tmp := make([]byte, len(f.data))
	ctr.XORKeyStream(tmp, f.data)

	// Decode and return the secret. If this fails, report that the passphrase
	// was invalid.
	sec, err := f.checkKey(tmp)
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
	*f = File{} // reset
	ctr, err := f.keyCipher(passphrase)
	if err != nil {
		return fmt.Errorf("keyfile encrypt: %w", err)
	}

	// Package and encrypt the secret.
	pkt := make([]byte, len(secret)+4) // +4 for checksum
	binary.BigEndian.PutUint32(pkt, f.checksum(secret))
	ctr.XORKeyStream(pkt[:4], pkt[:4])
	ctr.XORKeyStream(pkt[4:], secret)
	f.data = pkt
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

// keyIV returns the initialization vector, creating it if necessary.
func (f *File) keyIV() ([]byte, error) {
	if len(f.init) == 0 {
		f.init = make([]byte, aes.BlockSize)
		if _, err := rand.Read(f.init); err != nil {
			return nil, err
		}
	}
	return f.init, nil
}

// keyCipher returns an CTR mode stream for f using the given passphrase.
func (f *File) keyCipher(passphrase string) (cipher.Stream, error) {
	salt, err := f.keySalt()
	if err != nil {
		return nil, fmt.Errorf("key salt: %w", err)
	}
	ckey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, aesKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}

	iv, err := f.keyIV()
	if err != nil {
		return nil, fmt.Errorf("initialization vector: %w", err)
	}
	blk, err := aes.NewCipher(ckey)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(blk, iv), nil
}

// checkKey decodes a decrypted key wrapper and performs correctness checks.
// On success it returns the payload; otherwise ErrBadPassphrase.
func (f *File) checkKey(data []byte) ([]byte, error) {
	want := f.checksum(data[4:])
	got := binary.BigEndian.Uint32(data)
	if got != want {
		return nil, ErrBadPassphrase
	}
	return data[4:], nil
}

// checksum computes a IEEE CRC32 for the given data and key material.
func (f *File) checksum(data []byte) uint32 {
	crc := crc32.NewIEEE()
	crc.Write(f.init)
	crc.Write(f.salt)
	crc.Write(data)
	return crc.Sum32()
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
