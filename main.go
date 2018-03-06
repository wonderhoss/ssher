package main

import (
	"os/user"
	//    "regexp"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
)

var home string

//func isAuthorityCallback(auth ssh.PublicKey, address string) bool {
//    fmt.Println("auth callback called")
//        fmt.Printf("address: %s", address)
//    r, _ := regexp.Compile(".*\\.pusherplatform\\.io")
// TODO: check key against key from known_hosts file
//    fmt.Printf("Matches? %v", r.MatchString(address))
//    return r.MatchString(address)
//}

func init() {
	usr, err := user.Current()
	if err != nil {
		fmt.Println("Warn: unable to locate user home. Key file inference will not work.")
	} else {
		home = usr.HomeDir
	}
}

func main() {
	certChecker := &ssh.CertChecker{
		IsHostAuthority: isAuthorityCallback,
		HostKeyFallback: hostKeyFallback,
	}

	sshConfig := &ssh.ClientConfig{
		User: "core",
		Auth: []ssh.AuthMethod{
			newCertAuthMethod("/Users/pt/.ssh/id_elements_rsa", "/Users/pt/.ssh/id_elements_rsa-cert.pub"),
		},
		HostKeyCallback: certChecker.CheckHostKey,
	}

	client, err := ssh.Dial("tcp", "somehost:22", sshConfig)

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
