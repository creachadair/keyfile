# keyfile

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/creachadair/keyfile)

The `keyfile` package provides an interface to read and write encryption keys
and other sensitive secrets in a persistent format protected by a passphrase.
The passphrase is expanded to an encryption key using the scrypt algorithm, and
used to symmetrically encrypt key material with AES-256.
