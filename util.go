package keyfile

import (
	"os"
)

// LoadKey is a convenience function to load the contents of a single key from
// a stored binary-format keyfile.
func LoadKey(path, passphrase string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	kf, err := Load(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return kf.Get(passphrase)
}
