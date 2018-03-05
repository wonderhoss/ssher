package main

import (
    "bytes"
    "os"
    "errors"
    "net"
    "regexp"
    "log"
    "fmt"
    "bufio"
    "io/ioutil"
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/knownhosts"
)

func PublicKeyFileCert(file string, certfile string) ssh.AuthMethod {
        fmt.Println("Reading private key file")
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
            fmt.Println(err)
            fmt.Println("returning nil")
	    return nil
	}

        fmt.Println("Parsing private key")
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
            fmt.Println(err)
            fmt.Println("returning nil")
	    return nil
	}

        fmt.Println("Reading cert file")
        buffer, err = ioutil.ReadFile(certfile)
        if err != nil {
            fmt.Println(err)
            fmt.Println("returning nil")
            return nil
        }

        fmt.Println("Parsing cert")
        certKey, _, _, _, err := ssh.ParseAuthorizedKey(buffer)
        if err != nil {
            log.Fatal("unable to parse cert file: ", err)
        }

        cert, ok := certKey.(*ssh.Certificate)
        if !ok {
            log.Fatal("Unable to cast key to cert")
        }

        fmt.Println("Creating cert signer")
        certSigner, err := ssh.NewCertSigner(cert, key)
        if err != nil {
            log.Fatal("unable to create cert signer: %v", err)
        }

        fmt.Println("auth setup done")
	return ssh.PublicKeys(certSigner)
}

func findHostKey(hostname string) (*knownhosts.KnownKey, error) {
      kh, err := os.Open("/Users/pt/.ssh/known_hosts")
      if err != nil {
          log.Fatal("unable to read known hosts: %v", err)
      }

      scanner := bufio.NewScanner(kh)
      line := 0
      for scanner.Scan() {
          line += 1
          if len(scanner.Bytes()) == 0 { continue }
          marker, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
          if err != nil {
            log.Fatal("failed to parse known hosts ", err)
          }
          fmt.Printf("Now processing: %s, %s\n", marker, hosts)

          hx := knownhosts.Normalize(hostname)

          for _, h := range hosts {
            fmt.Printf("    h is currently: %#v\n", h)
            fmt.Printf("    comparing to: %#v\n", hx)
            if (h == hx) || (h == knownhosts.HashHostname(hx)) {
                ky := &knownhosts.KnownKey{
                    Key: pubKey,
                    Filename: "known_hosts",
                    Line: line,
                }
                return ky, nil
            }
          }
          if marker == "cert-authority" {
              fmt.Printf("%s, %s\n", marker, hosts)
// check hosts against pattern in ca
          }
          fmt.Println()
      }
      return nil, fmt.Errorf("No key for %s", hostname)
}

func isAuthorityCallback(auth ssh.PublicKey, address string) bool {
    r, _ := regexp.Compile(".*\\.pusherplatform\\.io")
// TODO: check key against key from known_hosts file
    return r.MatchString(address)
}

func fallback(hostname string, _ net.Addr, pubkey ssh.PublicKey) error {
    knownKey, err := findHostKey(hostname)
    if err != nil { return err }
    fmt.Println("host key: ", pubkey)
    fmt.Println("known:    ", knownKey) 
    if bytes.Equal(knownKey.Key.Marshal(), pubkey.Marshal()) {
        fmt.Println("keys match")
        return nil
    } else {
        fmt.Println("keys don't match")
        return &knownhosts.KeyError{
            Want: []knownhosts.KnownKey{*knownKey},
        }
    }
    return errors.New("I'm failing this because I can")
}

func main() {

    certChecker := &ssh.CertChecker {
      IsHostAuthority: isAuthorityCallback,
      HostKeyFallback: fallback,
    }

    sshConfig := &ssh.ClientConfig {
        User: "core",
        Auth: []ssh.AuthMethod {
            PublicKeyFileCert("/Users/pt/.ssh/id_elements_rsa", "/Users/pt/.ssh/id_elements_rsa-cert.pub"),
        },
        HostKeyCallback: certChecker.CheckHostKey,
        
    }

    fmt.Println("client config complete")
    client, err := ssh.Dial("tcp", "somehost:1022", sshConfig)
    if err != nil {
        log.Fatalf("unable to connect: %v", err)
    }
    defer client.Close()

    session, err := client.NewSession()
    if err != nil {
        log.Fatal("unable to establish session: %v", err)
    }

    out, err := session.Output("ls -la /")
    if err != nil {
        log.Fatal("unable to run command: %v", err)
    }
    
    fmt.Println(string(out[:]))

}
