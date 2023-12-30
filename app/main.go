package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	useForwardingResolver, resolverAddress := tryParseResolverArg()

	var resolver dns.DnsResolver
	var err error
	if useForwardingResolver {
		fmt.Println("Using forwarding resolver:", resolverAddress)
		resolver, err = dns.InitForwardingResolver(resolverAddress)
	} else {
		resolver, err = dns.InitInternalResolver()
	}

	if err != nil {
		fmt.Println("Failed to initialize resolver:", err)
		return
	}

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

		// Print the received data as decimal bytes
		fmt.Println("\n")
		for i := 0; i < size; i++ {
			fmt.Printf("%d ", buf[i])
		}
		fmt.Println("\n")

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

		response := resolver.Resolve(dnsRequest)
		respondWithMessage(udpConn, source, response)
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
