// Program keyfile is a command-line tool to create, read, and modify
// key files.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyfile"
	"golang.org/x/sys/unix"
)

var flags struct {
	EmptyOK bool `flag:"empty-ok,If true, an empty passphrase is allowed (not recommended)"`
}

var getFlags struct {
	Raw bool `flag:"raw,Write key output as binary"`
}

func main() {
	root := &command.C{
		Name:  command.ProgramName(),
		Usage: "<command> [args]\nhelp [<command>]",
		Help: `Create, read, or modify the contents of a keyfile.

Keys can be specified in various formats:

- The prefix "#x" indicates a string of hexadecimal digits (#x12ab).
- The prefix "@" indcates a base64 string (@Eqs=).
- The string "-" instructs the program to read the key from stdin.
- Otherwise a key argument is taken verbatim.`,
		SetFlags: command.Flags(flax.MustBind, &flags),

		Commands: []*command.C{
			{
				Name:     "get",
				Usage:    "<key-file>",
				Help:     "Print the contents of the key file to stdout.",
				SetFlags: command.Flags(flax.MustBind, &getFlags),
				Run: command.Adapt(func(env *command.Env, keyFile string) error {
					key, err := loadKeyFile("", keyFile)
					if err != nil {
						return err
					}
					if getFlags.Raw {
						os.Stdout.Write(key)
					} else {
						fmt.Println(base64.StdEncoding.EncodeToString(key))
					}
					return nil
				}),
			}, {
				Name:  "set",
				Usage: "<key-file> <key>",
				Help:  "Create or replace the contents of the key file with the given key.",
				Run: command.Adapt(func(env *command.Env, keyFile, keySpec string) error {
					key, err := decodeKey(keySpec)
					if err != nil {
						return fmt.Errorf("decoding key: %w", err)
					}
					kf, err := setKey("", key)
					if err != nil {
						return err
					}
					return saveKeyFile(keyFile, kf)
				}),
			}, {
				Name:  "rekey",
				Usage: "<key-file>",
				Help:  "Change the passphrase on an existing key file.",
				Run: command.Adapt(func(env *command.Env, keyFile string) error {
					key, err := loadKeyFile("Old ", keyFile)
					if err != nil {
						return err
					}
					kf, err := setKey("New ", key)
					if err != nil {
						return err
					}
					return saveKeyFile(keyFile, kf)
				}),
			}, {
				Name:  "random",
				Usage: "<key-file> <n>",
				Help:  "Write a randomly-generated key of n bytes to the key file.",
				Run: command.Adapt(func(env *command.Env, keyFile, size string) error {
					n, err := strconv.Atoi(size)
					if err != nil {
						return fmt.Errorf("invalid size: %w", err)
					} else if n <= 0 {
						return fmt.Errorf("n must be positive: %d", n)
					}

					kf := keyfile.New()
					pp, err := getPassphrase("", true)
					if err != nil {
						return err
					} else if _, err := kf.Random(pp, n); err != nil {
						return fmt.Errorf("generate random key: %w", err)
					}
					return saveKeyFile(keyFile, kf)
				}),
			}, {
				Name:  "offer",
				Usage: "<key-file> <socket-path>",
				Help: `Write the contents of a key file to a named pipe.

After reading the key file, offer opens a named pipe at the given path,
creating it if necessary. When the pipe is opened by a reader, it writes
the key, then closes (and, if created, removes) the pipe.`,

				Run: command.Adapt(func(env *command.Env, keyFile, pipeFile string) error {
					key, err := loadKeyFile("", keyFile)
					if err != nil {
						return err
					}
					ctx, cancel := signal.NotifyContext(env.Context(), syscall.SIGINT, syscall.SIGTERM)
					defer cancel()
					return offerKey(env.SetContext(ctx), pipeFile, key)
				}),
			},
			command.HelpCommand(nil),
			command.VersionCommand(),
		},
	}
	command.RunOrFail(root.NewEnv(nil), os.Args[1:])
}

func setKey(tag string, key []byte) (*keyfile.File, error) {
	kf := keyfile.New()
	pp, err := getPassphrase(tag, true)
	if err != nil {
		return nil, err
	}
	if err := kf.Set(pp, key); err != nil {
		return nil, err
	}
	return kf, nil
}

func saveKeyFile(path string, kf *keyfile.File) error {
	return atomicfile.Tx(path, 0600, func(f *atomicfile.File) error {
		_, err := f.Write(kf.Encode())
		return err
	})
}

func loadKeyFile(tag, path string) ([]byte, error) {
	key, err := keyfile.LoadKey(path, func() (string, error) {
		return getPassphrase(tag, false)
	})
	if err != nil {
		return nil, fmt.Errorf("load key file: %w", err)
	}
	return key, nil
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

func getPassphrase(tag string, confirm bool) (string, error) {
	pp, err := getpass.Prompt(tag + "Passphrase: ")
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	} else if pp == "" && flags.EmptyOK {
		return "", errors.New("empty passphrase")
	}
	if confirm {
		cf, err := getpass.Prompt("Confirm " + tag + "passphrase: ")
		if err != nil {
			return "", fmt.Errorf("read confirmation: %w", err)
		} else if cf != pp {
			return "", errors.New("passphrases do not match")
		}
	}
	return pp, nil
}

func offerKey(env *command.Env, pipeFile string, key []byte) error {
	fi, err := os.Stat(pipeFile)
	if err == nil {
		if fi.Mode().Type() != fs.ModeNamedPipe {
			return fmt.Errorf("file %q exists and is not a pipe", pipeFile)
		}
		// The pipe already exists, use it as-is.
	} else if err := unix.Mkfifo(pipeFile, 0600); err != nil {
		return fmt.Errorf("create pipe: %w", err)
	} else {
		defer os.Remove(pipeFile)
		// We created the pipe, clean it up when we're done.
	}

	// Opening the pipe to write will block waiting for a reader.  If the
	// context ends before we get one, unblock the open by opening our own
	// reader.
	ready := make(chan struct{})
	go func() {
		select {
		case <-env.Context().Done():
			f, err := os.Open(pipeFile)
			if err == nil {
				f.Close()
			}
		case <-ready:
			return // we succeeded, no need to clean up
		}
	}()

	f, err := os.OpenFile(pipeFile, os.O_WRONLY, fs.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf("open pipe: %w", err)
	} else if err := env.Context().Err(); err != nil {
		f.Close()
		return err
	}
	close(ready)

	// Reaching here, we got a real reader.
	_, werr := f.Write(key)
	if err := errors.Join(werr, f.Close()); err != nil {
		return fmt.Errorf("offering key: %w", err)
	}
	return nil
}
