# keyfile

http://godoc.org/bitbucket.org/creachadair/keyfile

[![Go Report Card](https://goreportcard.com/badge/bitbucket.org/creachadair/keyfile)](https://goreportcard.com/report/bitbucket.org/creachadair/keyfile)

The `keyfile` package provides an interface to read and write encryption keys
and other sensitive secrets in a persistent format protected by a passphrase.
The passphrase is expanded to an encryption key using the scrypt algorithm, and
used to symmetrically encrypt key material with AES-256.
