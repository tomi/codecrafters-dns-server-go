package dns

import (
	"fmt"
	"net"
	"time"
)

type ForwardingResolver struct {
	udpAddr *net.UDPAddr
	udpConn *net.UDPConn
}

func InitForwardingResolver(serverAddr string) (*ForwardingResolver, error) {
	// Resolve the UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return nil, err
	}

	// Create a UDP connection
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error dialing UDP:", err)
		return nil, err
	}

	return &ForwardingResolver{
		udpAddr: udpAddr,
		udpConn: udpConn,
	}, nil
}

func (r *ForwardingResolver) Resolve(msg *Message) *Message {
	answers := make([]ResourceRecord, 0)
	isValidRequest := msg.Header.Flags.OPCODE == 0
	returnCode := RCodeNoError
	if !isValidRequest {
		returnCode = RCodeNotImplemented
	}

	if isValidRequest {
		for _, question := range msg.Questions {
			answer, err := r.resolveQuestion(msg, &question)
			if err != nil {
				return makeErrorResponse(msg, RCodeServerFailure)
			}

			answers = append(answers, answer.Answers...)
		}
	}

	return &Message{
		Header: Header{
			ID: msg.Header.ID,
			Flags: Flags{
				QR:     true,
				OPCODE: msg.Header.OPCODE,
				AA:     false,
				TC:     false,
				RD:     msg.Header.RD,
				RA:     false,
				Z:      0,
				RCODE:  returnCode,
			},
			QDCOUNT: uint16(len(msg.Questions)),
			ANCOUNT: uint16(len(answers)),
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions: msg.Questions,
		Answers:   answers,
	}
}

func (r *ForwardingResolver) resolveQuestion(msg *Message, question *Question) (*Message, error) {
	requestMsg := questionToMessage(msg.Header.ID, question)

	// Serialize the question
	requestSerialized, err := requestMsg.Serialize()
	if err != nil {
		return nil, err
	}

	// Send a message to the server
	_, err = r.udpConn.Write(requestSerialized)
	if err != nil {
		return nil, err
	}

	// Set a deadline for reading the response from the server
	deadline := time.Now().Add(5 * time.Second)
	err = r.udpConn.SetReadDeadline(deadline)
	if err != nil {
		return nil, err
	}

	// Read response from the server
	buf := make([]byte, 512)
	size, source, err := r.udpConn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Received %d bytes from %s\n", size, source)

	// Deserialize the response
	response, err := DeserializeMessage(buf[:size])
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (r *ForwardingResolver) Close() {
	r.udpConn.Close()
}

func questionToMessage(id uint16, question *Question) *Message {
	return &Message{
		Header: Header{
			ID: id,
			Flags: Flags{
				QR:     false,
				OPCODE: OpcodeQuery,
				AA:     false,
				TC:     false,
				RD:     true,
				RA:     false,
				Z:      0,
				RCODE:  RCodeNoError,
			},
			QDCOUNT: 1,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions: []Question{
			*question,
		},
		Answers: make([]ResourceRecord, 0),
	}
}

func makeErrorResponse(msg *Message, code ResponseCode) *Message {
	return &Message{
		Header: Header{
			ID: msg.Header.ID,
			Flags: Flags{
				QR:     true,
				OPCODE: msg.Header.OPCODE,
				AA:     false,
				TC:     false,
				RD:     msg.Header.RD,
				RA:     false,
				Z:      0,
				RCODE:  code,
			},
			QDCOUNT: 0,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
	}
}
