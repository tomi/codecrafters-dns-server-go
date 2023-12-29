package dns

import (
	"encoding/binary"
	"fmt"
)

type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

func DeserializeMessage(data []byte) (*Message, error) {
	message := &Message{}

	header, err := DeserializeHeader(data[0:12])
	if err != nil {
		return nil, err
	}

	message.Header = *header
	message.Questions = make([]Question, 0)
	message.Answers = make([]ResourceRecord, 0)

	return message, nil
}

type Label string

type DomainName struct {
	Labels []Label
}

type ResourceRecordType uint16

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
const (
	TYPE_A     ResourceRecordType = 1  // a host address
	TYPE_NS    ResourceRecordType = 2  // an authoritative name server
	TYPE_MD    ResourceRecordType = 3  // a mail destination (Obsolete - use MX)
	TYPE_MF    ResourceRecordType = 4  // a mail forwarder (Obsolete - use MX)
	TYPE_CNAME ResourceRecordType = 5  // the canonical name for an alias
	TYPE_SOA   ResourceRecordType = 6  // marks the start of a zone of authority
	TYPE_MB    ResourceRecordType = 7  // a mailbox domain name (EXPERIMENTAL)
	TYPE_MG    ResourceRecordType = 8  // a mail group member (EXPERIMENTAL)
	TYPE_MR    ResourceRecordType = 9  // a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL  ResourceRecordType = 10 // a null RR (EXPERIMENTAL)
	TYPE_WKS   ResourceRecordType = 11 // a well known service description
	TYPE_PTR   ResourceRecordType = 12 // a domain name pointer
	TYPE_HINFO ResourceRecordType = 13 // host information
	TYPE_MINFO ResourceRecordType = 14 // mailbox or mail list information
	TYPE_MX    ResourceRecordType = 15 // mail exchange
	TYPE_TXT   ResourceRecordType = 16 // text strings
)

type ResourceRecordClass uint16

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
const (
	CLASS_IN ResourceRecordClass = 1 // the Internet
	CLASS_CS ResourceRecordClass = 2 // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH ResourceRecordClass = 3 // the CHAOS class
	CLASS_HS ResourceRecordClass = 4 // Hesiod [Dyer 87]
)

type Question struct {
	// A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets
	Name  DomainName
	Type  ResourceRecordType
	Class ResourceRecordClass
}

type ResourceRecord struct {
	Name  DomainName
	Type  ResourceRecordType
	Class ResourceRecordClass
	TTL   uint32
	RData []byte
}

func (d *DomainName) Serialize() ([]byte, error) {
	buf := make([]byte, 0)

	for _, label := range d.Labels {
		labelLength := len(label)
		// The high order two bits of every length octet must be zero, and the
		// remaining six bits of the length field limit the label to 63 octets or
		// less.
		if labelLength > 63 {
			return nil, fmt.Errorf("label length %d exceeds maximum of 63", labelLength)
		}

		buf = append(buf, byte(labelLength))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0)

	return buf, nil
}

func bitToBool(bit byte) bool {
	return bit&0x01 == 1
}

func uint16ToBytes(value uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return buf
}

func uint32ToBytes(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

func (q *Question) Serialize() ([]byte, error) {
	buf := make([]byte, 0)

	domainNameSerialized, err := q.Name.Serialize()
	if err != nil {
		return nil, err
	}

	typeSerialized := uint16ToBytes(uint16(q.Type))
	classSerialized := uint16ToBytes(uint16(q.Class))

	buf = append(buf, domainNameSerialized...)
	buf = append(buf, typeSerialized...)
	buf = append(buf, classSerialized...)

	return buf, nil
}

func SerializeQuestions(questions []Question) ([]byte, error) {
	buf := make([]byte, 0)

	for _, question := range questions {
		questionSerialized, err := question.Serialize()
		if err != nil {
			return nil, err
		}

		buf = append(buf, questionSerialized...)
	}

	return buf, nil
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

func SerializeAnswers(answers []ResourceRecord) ([]byte, error) {
	buf := make([]byte, 0)

	for _, answer := range answers {
		answerSerialized, err := answer.Serialize()
		if err != nil {
			return nil, err
		}

		buf = append(buf, answerSerialized...)
	}

	return buf, nil
}

func (m *Message) Serialize() ([]byte, error) {
	buf := make([]byte, 0)

	headerSerialized := m.Header.Serialize()
	questionsSerialized, err := SerializeQuestions(m.Questions)
	if err != nil {
		return nil, err
	}

	answersSerialized, err := SerializeAnswers(m.Answers)
	if err != nil {
		return nil, err
	}

	buf = append(buf, headerSerialized...)
	buf = append(buf, questionsSerialized...)
	buf = append(buf, answersSerialized...)

	return buf, nil
}
