package dns

func serializeAnswers(answers []ResourceRecord) ([]byte, error) {
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

func deserializeAnswers(buf []byte, offset int, count uint16) ([]ResourceRecord, error) {
	answers := make([]ResourceRecord, 0)

	for i := uint16(0); i < count; i++ {
		bytesRead, answer, err := deserializeResourceRecord(buf, offset)
		if err != nil {
			return nil, err
		}

		offset += bytesRead
		answers = append(answers, *answer)
	}

	return answers, nil
}
