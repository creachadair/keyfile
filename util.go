package keyfile

import (
	"io"
	"os"
)

// LoadKey is a convenience function to load the contents of a single key from
// a stored binary-format keyfile.
func LoadKey(path, slug, passphrase string) ([]byte, error) {
	return loadKey(path, slug, passphrase, Load)
}

// LoadKeyJSON is a convenience function to load the contents of a single key
// from a stored JSON-encoded keyfile.
func LoadKeyJSON(path, slug, passphrase string) ([]byte, error) {
	return loadKey(path, slug, passphrase, LoadJSON)
}

func loadKey(path, slug, passphrase string, load func(io.Reader) (*File, error)) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	kf, err := load(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return kf.Get(slug, passphrase)
}
