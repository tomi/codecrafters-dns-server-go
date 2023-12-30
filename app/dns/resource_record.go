package dns

type ResourceRecordType uint16

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
const (
	TYPE_A     ResourceRecordType = 1  // a host address
	TYPE_NS                       = 2  // an authoritative name server
	TYPE_MD                       = 3  // a mail destination (Obsolete - use MX)
	TYPE_MF                       = 4  // a mail forwarder (Obsolete - use MX)
	TYPE_CNAME                    = 5  // the canonical name for an alias
	TYPE_SOA                      = 6  // marks the start of a zone of authority
	TYPE_MB                       = 7  // a mailbox domain name (EXPERIMENTAL)
	TYPE_MG                       = 8  // a mail group member (EXPERIMENTAL)
	TYPE_MR                       = 9  // a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL                     = 10 // a null RR (EXPERIMENTAL)
	TYPE_WKS                      = 11 // a well known service description
	TYPE_PTR                      = 12 // a domain name pointer
	TYPE_HINFO                    = 13 // host information
	TYPE_MINFO                    = 14 // mailbox or mail list information
	TYPE_MX                       = 15 // mail exchange
	TYPE_TXT                      = 16 // text strings
)

type ResourceRecordClass uint16

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
const (
	CLASS_IN ResourceRecordClass = 1 // the Internet
	CLASS_CS                     = 2 // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH                     = 3 // the CHAOS class
	CLASS_HS                     = 4 // Hesiod [Dyer 87]
)

//		                              1  1  1  1  1  1
//		0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                                               |
//	 /                                               /
//	 /                      NAME                     /
//	 |                                               |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                      TYPE                     |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                     CLASS                     |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                      TTL                      |
//	 |                                               |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	 |                   RDLENGTH                    |
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//	 /                     RDATA                     /
//	 /                                               /
//	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type ResourceRecord struct {
	// a domain name to which this resource record pertains.
	Name DomainName
	// two octets containing one of the RR type codes.  This
	// field specifies the meaning of the data in the RDATA
	// field.
	Type ResourceRecordType
	// two octets which specify the class of the data in the
	// RDATA field.
	Class ResourceRecordClass
	// A 32 bit unsigned integer that specifies the time interval (in seconds)
	// that the resource record may becached before it should be discarded.
	// Zero values are interpreted to mean that the RR can only be used for the
	// transaction in progress, and should not be cached.
	TTL uint32
	// A variable length string of octets that describes the resource. The
	// format of this information varies according to the TYPE and CLASS
	// of the resource record. For example, the if the TYPE is A and the
	// CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
	RData []byte
}

func (r *ResourceRecord) Serialize() ([]byte, error) {
	buf := make([]byte, 0)

	domainNameSerialized, err := r.Name.Serialize()
	if err != nil {
		return nil, err
	}

	typeSerialized := uint16ToBytes(uint16(r.Type))
	classSerialized := uint16ToBytes(uint16(r.Class))
	ttlSerialized := uint32ToBytes(r.TTL)
	rdLengthSerialized := uint16ToBytes(uint16(len(r.RData)))

	buf = append(buf, domainNameSerialized...)
	buf = append(buf, typeSerialized...)
	buf = append(buf, classSerialized...)
	buf = append(buf, ttlSerialized...)
	buf = append(buf, rdLengthSerialized...)
	buf = append(buf, r.RData...)

	return buf, nil
}

func deserializeResourceRecord(buf []byte, offset int) (int, *ResourceRecord, error) {
	bytesRead, domainName, err := deserializeDomainName(buf, offset)
	if err != nil {
		return 0, nil, err
	}

	typeBytesRead, rrType, err := deserializeType(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}
	bytesRead += typeBytesRead

	classBytesRead, rrClass, err := deserializeClass(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}
	bytesRead += classBytesRead

	ttlBytesRead, ttl, err := deserializeTtl(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}
	bytesRead += ttlBytesRead

	rdLengthBytesRead, rdLength, err := deserializeRdLength(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}
	bytesRead += rdLengthBytesRead

	rData := buf[offset+bytesRead : offset+bytesRead+int(rdLength)]
	bytesRead += int(rdLength)

	return bytesRead, &ResourceRecord{
		Name:  *domainName,
		Type:  rrType,
		Class: rrClass,
		TTL:   ttl,
		RData: rData,
	}, nil
}

func deserializeType(buf []byte, offset int) (int, ResourceRecordType, error) {
	maybeType, err := uint16FromBytes(buf[offset : offset+2])
	if err != nil {
		return 0, 0, err
	}
	rrType := ResourceRecordType(maybeType)

	return 2, rrType, nil
}

func deserializeClass(buf []byte, offset int) (int, ResourceRecordClass, error) {
	maybeClass, err := uint16FromBytes(buf[offset : offset+2])
	if err != nil {
		return 0, 0, err
	}
	rrClass := ResourceRecordClass(maybeClass)

	return 2, rrClass, nil
}

func deserializeTtl(buf []byte, offset int) (int, uint32, error) {
	maybeTtl, err := uint32FromBytes(buf[offset : offset+4])
	if err != nil {
		return 0, 0, err
	}
	ttl := uint32(maybeTtl)

	return 4, ttl, nil
}

func deserializeRdLength(buf []byte, offset int) (int, uint16, error) {
	maybeRdLength, err := uint16FromBytes(buf[offset : offset+2])
	if err != nil {
		return 0, 0, err
	}
	rdLength := uint16(maybeRdLength)

	return 2, rdLength, nil
}
