package main

import (
        "crypto/tls"
        "fmt"
        "log"
        "strings"
)

//Change the target below to test the vulnerability on, default SSL port is 443
var checkVulnerability = "phineas.io:443"

func main() {
        tlsConfiguration := &tls.Config{
                MinVersion:         tls.VersionTLS12,
                InsecureSkipVerify: true,
                ClientSessionCache: tls.NewLRUClientSessionCache(32),
        }

        connection, err := tls.Dial("tcp", checkVulnerability, tlsConfiguration)
        if err != nil {
                log.Fatalln("Failed to connect:", err)
        }
        connection.Close()

        connection, err = tls.Dial("tcp", checkVulnerability, tlsConfiguration)
        if err != nil && strings.Contains(err.Error(), "unexpected message") {
                fmt.Println(checkVulnerability, "appears to be vulnerable to Ticketbleed")
        } else if err != nil {
                log.Fatalln("Could not reconnect...", err)
        } else {
                fmt.Println(checkVulnerability, "doesn't show vulnerabilities linked to Ticketbleed")
                connection.Close()
        }
}
