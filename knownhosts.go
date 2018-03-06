package main

import (
	"bufio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"log"
	"os"
)

func getCAKeyForAddress(address string) (ssh.PublicKey, error) {
	kh, err := os.Open(home + "/.ssh/known_hosts")
	if err != nil {
		log.Println("unable to read known hosts: %v", err)
		return nil, err
	}

	hx := knownhosts.Normalize(address)

	scanner := bufio.NewScanner(kh)
	line := 0
	for scanner.Scan() {
		line += 1
		if len(scanner.Bytes()) == 0 {
			continue
		}
		marker, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			log.Println("warn: failed to parse known hosts ", err)
			return nil, err
		}
		if marker == "cert-authority" {
			for _, h := range hosts {
				if wildcardMatch([]byte(h), []byte(hx)) {
					return pubKey, nil
				}
			}
		}
	}
	return nil, nil
}

func getHostKeyForName(hostname string) (*knownhosts.KnownKey, error) {
	kh, err := os.Open(home + "/.ssh/known_hosts")
	if err != nil {
		log.Println("unable to read known hosts: %v", err)
		return nil, err
	}
	hx := knownhosts.Normalize(hostname)

	scanner := bufio.NewScanner(kh)
	line := 0
	for scanner.Scan() {
		line += 1
		if len(scanner.Bytes()) == 0 {
			continue
		}
		marker, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			log.Println("failed to read known hosts ", err)
			return nil, err
		}

		if marker == "cert-authority" {
			continue
		}
		for _, h := range hosts {
			if (h == hx) || (h == knownhosts.HashHostname(hx)) {
				ky := &knownhosts.KnownKey{
					Key:      pubKey,
					Filename: home + "/.ssh/known_hosts",
					Line:     line,
				}
				return ky, nil
			}
		}
	}
	return nil, nil
}

func wildcardMatch(pat []byte, str []byte) bool {
	for {
		if len(pat) == 0 {
			return len(str) == 0
		}
		if len(str) == 0 {
			return false
		}

		if pat[0] == '*' {
			if len(pat) == 1 {
				return true
			}

			for j := range str {
				if wildcardMatch(pat[1:], str[j:]) {
					return true
				}
			}
			return false
		}

		if pat[0] == '?' || pat[0] == str[0] {
			pat = pat[1:]
			str = str[1:]
		} else {
			return false
		}
	}
}
