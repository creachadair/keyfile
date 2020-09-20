package keyfile

import "io/ioutil"

// LoadKey is a convenience function to load the contents of a single key from
// a stored binary-format keyfile.
func LoadKey(path, passphrase string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kf, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return kf.Get(passphrase)
}
