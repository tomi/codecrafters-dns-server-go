package dns

import (
	"encoding/binary"
	"fmt"
)

type OpCode byte

const (
	OpcodeQuery        OpCode = 0 // a standard query (QUERY)
	OpCodeInverseQuery        = 1 // an inverse query (IQUERY)
	OpCodeStatus              = 2 // a server status request (STATUS)
	// 3-15            reserved for future use
)

type ResponseCode byte

const (
	// No error condition
	RCodeNoError ResponseCode = 0
	// Format error - The name server was unable to interpret the query.
	RCodeFormatError = 1
	// Server failure - The name server was unable to process this query due
	// to a problem with the name server.
	RCodeServerFailure = 2
	// Name Error - Meaningful only for responses from an authoritative name
	// server, this code signifies that the domain name referenced in the query
	// does not exist.
	RCodeNameError = 3
	// Not Implemented - The name server does not support the requested
	// kind of query.
	RCodeNotImplemented = 4
	// Refused - The name server refuses to perform the specified operation
	// for policy reasons.  For example, a name server may not wish to provide
	// the information to the particular requester, or a name server may not
	// wish to perform a particular operation (e.g., zone transfer) for
	// particular data.
	RCodeRefused = 5
	// 6-15            Reserved for future use.
)

//		                              1  1  1  1  1  1
//		0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Flags struct {
	// Query/Response indicator, 1 for reply, 0 for question
	QR bool
	// Operation code. Specifies the kind of query in a message.
	OPCODE OpCode
	// Authoritative Answer. 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	AA bool
	// Truncation. 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	TC bool
	// Recursion Desired. Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	RD bool
	// Recursion Available. Server sets this to 1 to indicate that recursion is available.
	RA bool
	// Reserved. Used by DNSSEC queries. At inception, it was reserved for future use.
	Z uint16
	// Response code indicating the status of the response.
	RCODE ResponseCode
}

//		                              1  1  1  1  1  1
//		0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                      ID                       |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    FLAGS                      |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    QDCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    ANCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    NSCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                    ARCOUNT                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Header struct {
	ID uint16
	Flags
	// Question count
	QDCOUNT uint16
	// Answer record count
	ANCOUNT uint16
	// Authority record count
	NSCOUNT uint16
	// Additional record count
	ARCOUNT uint16
}

// Serializes the header flags into a uint16.
func (f *Flags) Serialize() uint16 {
	flags := uint16(0)
	if f.QR {
		flags |= 1 << 15
	}
	flags |= uint16(f.OPCODE) << 11
	if f.AA {
		flags |= 1 << 10
	}
	if f.TC {
		flags |= 1 << 9
	}
	if f.RD {
		flags |= 1 << 8
	}
	if f.RA {
		flags |= 1 << 7
	}
	flags |= f.Z << 6
	flags |= uint16(f.RCODE)
	return flags
}

// Serializes the header into a byte slice.
func (h *Header) Serialize() []byte {
	buf := make([]byte, 12)

	binary.BigEndian.PutUint16(buf[0:], h.ID)
	binary.BigEndian.PutUint16(buf[2:], h.Flags.Serialize())
	binary.BigEndian.PutUint16(buf[4:], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:], h.ARCOUNT)

	return buf
}

func DeserializeFlags(data []byte) *Flags {
	flags := &Flags{}

	flags.QR = bitToBool(data[0] >> 7)
	flags.OPCODE = OpCode((data[0] >> 3) & 0x0F)
	flags.AA = bitToBool(data[0] >> 2)
	flags.TC = bitToBool(data[0] >> 1)
	flags.RD = bitToBool(data[0])

	flags.RA = bitToBool(data[1] >> 7)
	flags.Z = uint16(data[1] >> 6)
	flags.RCODE = ResponseCode(data[1] & 0x0F)

	return flags
}

func DeserializeHeader(data []byte) (*Header, error) {
	header := &Header{}

	if len(data) < 12 {
		return nil, fmt.Errorf("header is too short")
	}

	header.ID = binary.BigEndian.Uint16(data[0:])
	header.Flags = *DeserializeFlags(data[2:])
	header.QDCOUNT = binary.BigEndian.Uint16(data[4:])
	header.ANCOUNT = binary.BigEndian.Uint16(data[6:])
	header.NSCOUNT = binary.BigEndian.Uint16(data[8:])
	header.ARCOUNT = binary.BigEndian.Uint16(data[10:])

	return header, nil
}
