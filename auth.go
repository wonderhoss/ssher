package main

import (
	"bytes"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"log"
	"net"
)

func newCertAuthMethod(keyfile string, certfile string) ssh.AuthMethod {

	if keyfile == "" {
		keyfile = home + "/.ssh/id_rsa"
		log.Printf("SSH keyfile not specified. Using default (%s)", keyfile)
	}
	if certfile == "" {
		keyfile = home + "/.ssh/id_rsa-cert.pub"
		log.Printf("SSH keyfile not specified. Using default (%s)", certfile)
	}

	buffer, err := ioutil.ReadFile(keyfile)
	if err != nil {
		log.Fatal("Failed to read SSH keyfile: ", err)
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatal("Failed to parse SSH keyfile: ", err)
	}

	buffer, err = ioutil.ReadFile(certfile)
	if err != nil {
		log.Fatal("Failed to read SSH certificate: ", err)
	}
	c, _, _, _, err := ssh.ParseAuthorizedKey(buffer)
	if err != nil {
		log.Fatal("Failed to parse SSH certificate: ", err)
	}
	cert, ok := c.(*ssh.Certificate)
	if !ok {
		log.Fatal("Provided certificate is not an SSH certificate")
	}

	certSigner, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		log.Fatal("unable to create cert signer: ", err)
	}

	return ssh.PublicKeys(certSigner)
}

func isAuthorityCallback(auth ssh.PublicKey, address string) bool {
	cakey, err := getCAKeyForAddress(address)
	if err != nil {
		return false
	}
	if cakey == nil {
		return false
	}

	ret := bytes.Equal(auth.Marshal(), cakey.Marshal())
	return ret
}

func hostKeyFallback(hostname string, _ net.Addr, pubkey ssh.PublicKey) error {
	knownKey, err := getHostKeyForName(hostname)
	if err != nil {
		return err
	}

	if knownKey == nil {
		return &knownhosts.KeyError{}
	}

	if !bytes.Equal(knownKey.Key.Marshal(), pubkey.Marshal()) {
		return &knownhosts.KeyError{
			Want: []knownhosts.KnownKey{*knownKey},
		}
	}

	return nil
}
