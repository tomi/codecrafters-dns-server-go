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

		dnsRequest, err := dns.DeserializeMessage(buf[:size])
		if err != nil {
			fmt.Println("Failed to deserialize request:", err)
			response := dns.Message{
				Header: dns.Header{
					ID: dnsRequest.Header.ID,
					Flags: dns.Flags{
						QR:     true,
						OPCODE: dnsRequest.Header.Flags.OPCODE,
						AA:     false,
						TC:     false,
						RD:     dnsRequest.Header.Flags.RD,
						RA:     false,
						Z:      0,
						RCODE:  dns.RCodeFormatError,
					},
					QDCOUNT: 0,
					ANCOUNT: 0,
					NSCOUNT: 0,
					ARCOUNT: 0,
				},
			}

			respondWithMessage(udpConn, source, &response)

			continue
		}

		answers := []dns.ResourceRecord{
			{
				Name:  dnsRequest.Questions[0].Name,
				Type:  dns.TYPE_A,
				Class: dns.CLASS_IN,
				TTL:   60,
				RData: []byte{8, 8, 8, 8},
			},
		}

		isValidRequest := dnsRequest.Header.Flags.OPCODE == 0
		returnCode := dns.RCodeNoError
		if !isValidRequest {
			returnCode = dns.RCodeNotImplemented
		}

		response := dns.Message{
			Header: dns.Header{
				ID: dnsRequest.Header.ID,
				Flags: dns.Flags{
					QR:     true,
					OPCODE: dnsRequest.Header.Flags.OPCODE,
					AA:     false,
					TC:     false,
					RD:     dnsRequest.Header.Flags.RD,
					RA:     false,
					Z:      0,
					RCODE:  returnCode,
				},
				QDCOUNT: 1,
				ANCOUNT: 1,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			Questions: dnsRequest.Questions,
			Answers:   answers,
		}

		respondWithMessage(udpConn, source, &response)
	}
}

func respondWithMessage(udpConn *net.UDPConn, source *net.UDPAddr, message *dns.Message) {
	serializedResponse, err := message.Serialize()
	if err != nil {
		fmt.Println("Failed to serialize response:", err)
		return
	}

	_, err = udpConn.WriteToUDP(serializedResponse, source)
	if err != nil {
		fmt.Println("Failed to send response:", err)
	}

}
