package dns

//	                              1  1  1  1  1  1
//	0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Question struct {
	// A domain name represented as a sequence of labels, where each label
	// consists of a length octet followed by that number of octets
	Name  DomainName
	Type  ResourceRecordType
	Class ResourceRecordClass
}

// Serializes the question into a byte slice.
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

// Serializes a slice of questions into a byte slice.
func serializeQuestions(questions []Question) ([]byte, error) {
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

func deserializeQuestion(buf []byte, offset int) (int, *Question, error) {
	bytesRead, domainName, err := deserializeDomainName(buf, offset)
	if err != nil {
		return 0, nil, err
	}

	typeBytesRead, qtype, err := deserializeType(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}

	bytesRead += typeBytesRead

	classBytesRead, qclass, err := deserializeClass(buf, offset+bytesRead)
	if err != nil {
		return 0, nil, err
	}

	bytesRead += classBytesRead

	return bytesRead, &Question{
		Name:  *domainName,
		Type:  qtype,
		Class: qclass,
	}, nil
}

func deserializeQuestions(buf []byte, offset int, count uint16) (int, []Question, error) {
	startOffset := offset
	questions := make([]Question, 0)

	for i := uint16(0); i < count; i++ {
		bytesRead, question, err := deserializeQuestion(buf, offset)
		if err != nil {
			return 0, nil, err
		}

		offset += bytesRead
		questions = append(questions, *question)
	}

	return offset - startOffset, questions, nil
}
