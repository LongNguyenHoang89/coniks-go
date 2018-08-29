package client

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/utils"
)

// Config contains the client's configuration needed to send a request to a
// CONIKS server: the path to the server's signing public-key file
// and the actual public-key parsed from that file; the server's addresses
// for sending registration requests and other types of requests,
// respectively.
//
// Note that if RegAddress is empty, the client falls back to using Address
// for all request types.
type Config struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`

	SigningPubKey sign.PublicKey

	RegAddress string `toml:"registration_address,omitempty"`
	Address    string `toml:"address"`

	ServerAddress *ServerAddress `toml:"server-address,omitempty"`
}

// A ServerAddress describes a ConiksClient server connection.
// The address must be specified explicitly.
// Additionally, HTTP connections must use TLS for added security,
// and each is required to specify a TLS certificate and corresponding
// private key.
type ServerAddress struct {
	// Address is formatted as : https://address:port
	Address string `toml:"address"`
	// TLSCertPath is a path to the server's TLS Certificate,
	// which has to be set if the connection is TCP.
	TLSCertPath string `toml:"cert"`
	// TLSKeyPath is a path to the server's TLS private key,
	// which has to be set if the connection is TCP.
	TLSKeyPath string `toml:"key"`
}

// LoadConfig returns a client's configuration read from the given filename.
// It reads the signing public-key file and parses the actual key.
// If there is any parsing or IO-error it returns an error (and the returned
// config will be nil).
func LoadConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := utils.ResolvePath(conf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	conf.SigningPubKey = signPubKey

	// also update path for TLS cert files
	if conf.ServerAddress != nil {
		conf.ServerAddress.TLSCertPath = utils.ResolvePath(conf.ServerAddress.TLSCertPath, file)
		conf.ServerAddress.TLSKeyPath = utils.ResolvePath(conf.ServerAddress.TLSKeyPath, file)
	}

	return &conf, nil
}
