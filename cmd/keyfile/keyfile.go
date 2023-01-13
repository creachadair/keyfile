// Program keyfile is a command-line tool to create, read, and modify
// key files.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyfile"
)

var (
	doGet    = flag.Bool("get", false, "Read the contents of the keyfile")
	doRaw    = flag.Bool("raw", false, "Write keyfile contents without encoding (with -get)")
	doSet    = flag.String("set", "", "Write this string to the keyfile")
	doRekey  = flag.Bool("rekey", false, "Change the passphrase on the keyfile")
	doRandom = flag.Int("random", 0, "Write a random key to the keyfile")
	emptyOK  = flag.Bool("empty-ok", false, "If true, an empty passphrase is allowed")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s -get <keyfile-path>
       %[1]s -set <key> <keyfile-path>
       %[1]s -rekey <keyfile-path>

Create, read, or modify the contents of a keyfile.

With -get, read the current contents of the file and print them to stdout
encoded as base64. Include -raw to write the contents without encoding.

With -set, create or replace the file with the specified key.
- If key has the prefix "#x" it is treated as a string of hexadecimal digits.
- If key has the prefix "@" it is treated as a base64 string.
- If key is the string "-" the key is read from stdin.
Otherwise key is taken verbatim.

With -rekey, rewrite the file with a new passphrase.

Options:
`, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	filePath := flag.Arg(0)
	if filePath == "" {
		log.Fatalf("You must specify a key file path; use '%s -help'",
			filepath.Base(os.Args[0]))
	} else if countOpts() > 1 {
		log.Fatal("At most one of -read, -write, -random, and -rekey may be set")
	}
	switch {
	case *doGet:
		key := mustReadKeyfile("", filePath)
		if *doRaw {
			os.Stdout.Write(key)
		} else {
			fmt.Println(base64.StdEncoding.EncodeToString(key))
		}

	case *doSet != "":
		key, err := decodeKey(*doSet)
		if err != nil {
			log.Fatalf("Decoding key: %v", err)
		}
		mustWriteKeyFile(filePath, mustSetKey("", key))

	case *doRekey:
		old := mustReadKeyfile("Old ", filePath)
		mustWriteKeyFile(filePath, mustSetKey("New ", old))

	case *doRandom > 0:
		kf := keyfile.New()
		if _, err := kf.Random(mustPassphrase(""), *doRandom); err != nil {
			log.Fatalf("Generating random key: %v", err)
		}
		mustWriteKeyFile(filePath, kf)

	default:
		log.Fatal("No operation selected (use -get, -set, -random, or -rekey)")
	}
}

func mustSetKey(tag string, key []byte) *keyfile.File {
	kf := keyfile.New()
	if err := kf.Set(mustPassphrase(tag), key); err != nil {
		log.Fatalf("Encoding keyfile: %v", err)
	}
	return kf
}

func mustWriteKeyFile(path string, kf *keyfile.File) {
	of, err := atomicfile.New(path, 0600)
	if err != nil {
		log.Fatalf("Creating output file: %v", err)
	} else if _, err := of.Write(kf.Encode()); err != nil {
		of.Cancel()
		log.Fatalf("Writing output: %v", err)
	} else if err := of.Close(); err != nil {
		log.Fatalf("Closing output: %v", err)
	}
}

func mustReadKeyfile(tag, path string) []byte {
	key, err := keyfile.LoadKey(path, func() (string, error) {
		return mustPassphrase(tag), nil
	})
	if err != nil {
		log.Fatalf("Loading keyfile: %v", err)
	}
	return key
}

func decodeKey(s string) ([]byte, error) {
	if s == "-" {
		return io.ReadAll(os.Stdin)
	} else if t := strings.TrimPrefix(s, "#x"); t != s {
		return hex.DecodeString(t)
	} else if t := strings.TrimPrefix(s, "@"); t != s {
		return base64.StdEncoding.DecodeString(t)
	}
	return []byte(s), nil
}

func mustPassphrase(tag string) string {
	pp, err := getpass.Prompt(tag + "Passphrase: ")
	if err != nil {
		log.Fatalf("Reading passsphrase: %v", err)
	} else if pp == "" && !*emptyOK {
		log.Fatal("Empty passphrase")
	}
	return pp
}

func countOpts() (opts int) {
	if *doGet {
		opts++
	}
	if *doSet != "" {
		opts++
	}
	if *doRekey {
		opts++
	}
	if *doRandom > 0 {
		opts++
	}
	return
}
