package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		questions := []dns.Question{
			dns.Question{
				Name: dns.DomainName{
					Labels: []dns.Label{"codecrafters", "io"},
				},
				Type:  dns.TYPE_A,
				Class: dns.CLASS_IN,
			},
		}

		response := dns.Message{
			Header: dns.Header{
				ID: 1234,
				Flags: dns.Flags{
					QR:     1,
					OPCODE: 0,
					AA:     0,
					TC:     0,
					RD:     0,
					RA:     0,
					Z:      0,
					RCODE:  0,
				},
				QDCOUNT: 1,
				ANCOUNT: 0,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			Questions: questions,
		}

		serializedResponse, err := response.Serialize()
		if err != nil {
			fmt.Println("Failed to serialize response:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(serializedResponse, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
