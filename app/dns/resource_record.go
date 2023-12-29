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
