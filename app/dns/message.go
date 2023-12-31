package dns

type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

func DeserializeMessage(data []byte) (*Message, error) {
	message := &Message{}

	header, err := deserializeHeader(data[0:12])
	if err != nil {
		return nil, err
	}

	bytesRead, questions, err := deserializeQuestions(data, 12, header.QDCOUNT)
	if err != nil {
		return nil, err
	}

	answers, err := deserializeAnswers(data, 12+bytesRead, header.ANCOUNT)
	if err != nil {
		return nil, err
	}

	message.Header = *header
	message.Questions = questions
	message.Answers = answers

	return message, nil
}

func (m *Message) Serialize() ([]byte, error) {
	buf := make([]byte, 0)

	headerSerialized := m.Header.Serialize()
	questionsSerialized, err := serializeQuestions(m.Questions)
	if err != nil {
		return nil, err
	}

	answersSerialized, err := serializeAnswers(m.Answers)
	if err != nil {
		return nil, err
	}

	buf = append(buf, headerSerialized...)
	buf = append(buf, questionsSerialized...)
	buf = append(buf, answersSerialized...)

	return buf, nil
}
