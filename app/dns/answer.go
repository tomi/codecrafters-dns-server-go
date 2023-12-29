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
