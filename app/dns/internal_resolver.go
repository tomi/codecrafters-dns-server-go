package dns

type InternalResolver struct {
}

func InitInternalResolver() (*InternalResolver, error) {
	return &InternalResolver{}, nil
}

func (r *InternalResolver) Resolve(request *Message) *Message {
	answers := make([]ResourceRecord, 0)
	isValidRequest := request.Header.Flags.OPCODE == 0
	returnCode := RCodeNoError
	if !isValidRequest {
		returnCode = RCodeNotImplemented
	}

	if isValidRequest {
		for _, question := range request.Questions {
			answer := []ResourceRecord{
				{
					Name:  question.Name,
					Type:  TYPE_A,
					Class: CLASS_IN,
					TTL:   60,
					RData: []byte{8, 8, 8, 8},
				},
			}

			answers = append(answers, answer...)
		}
	}

	response := Message{
		Header: Header{
			ID: request.Header.ID,
			Flags: Flags{
				QR:     true,
				OPCODE: request.Header.Flags.OPCODE,
				AA:     false,
				TC:     false,
				RD:     request.Header.Flags.RD,
				RA:     false,
				Z:      0,
				RCODE:  returnCode,
			},
			QDCOUNT: uint16(len(request.Questions)),
			ANCOUNT: uint16(len(answers)),
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions: request.Questions,
		Answers:   answers,
	}

	return &response
}
