package dns

import "encoding/binary"

type Message struct {
	Header Header
}

type Flags struct {
	// Query/Response indicator, 4 bits
	QR uint16
	// Operation code
	OPCODE uint16
	// Authoritative Answer
	AA uint16
	// Truncation
	TC uint16
	// Recursion Desired
	RD uint16
	// Recursion Available
	RA uint16
	// Reserved
	Z uint16
	// Response code, 4 bits
	RCODE uint16
}

type Header struct {
	ID    uint16
	Flags Flags
	// Question count
	QDCOUNT uint16
	// Answer record count
	ANCOUNT uint16
	// Authority record count
	NSCOUNT uint16
	// Additional record count
	ARCOUNT uint16
}

func (f Flags) Serialize() uint16 {
	flags := uint16(0)
	flags |= f.QR << 15
	flags |= f.OPCODE << 11
	flags |= f.AA << 10
	flags |= f.TC << 9
	flags |= f.RD << 8
	flags |= f.RA << 7
	flags |= f.Z << 6
	flags |= f.RCODE
	return flags
}

func (h Header) Serialize() []byte {
	buf := make([]byte, 12)

	binary.BigEndian.PutUint16(buf[0:], h.ID)
	binary.BigEndian.PutUint16(buf[2:], h.Flags.Serialize())
	binary.BigEndian.PutUint16(buf[4:], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:], h.ARCOUNT)

	return buf
}

func (m Message) Serialize() []byte {
	return m.Header.Serialize()
}
