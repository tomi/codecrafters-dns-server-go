package dns

import "fmt"

type Label string

type DomainName struct {
	Labels []Label
}

const MAX_LABEL_LENGTH = 63

func (d *DomainName) Serialize() ([]byte, error) {
	// Labels are encoded as <length><content>, where <length> is a single byte
	// that specifies the length of the label, and <content> is the actual
	// content of the label. The sequence of labels is terminated by a null
	// byte (\x00).
	buf := make([]byte, 0)

	for _, label := range d.Labels {
		labelLength := len(label)
		// The high order two bits of every length octet must be zero, and the
		// remaining six bits of the length field limit the label to 63 octets or
		// less.
		if labelLength > MAX_LABEL_LENGTH {
			return nil, fmt.Errorf("label length %d exceeds maximum of 63", labelLength)
		}

		buf = append(buf, byte(labelLength))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0)

	return buf, nil
}

func deserializeDomainName(buf []byte) (int, *DomainName, error) {
	labels := make([]Label, 0)
	offset := 0

	readLength := func() (int, error) {
		if len(buf) < offset+1 {
			return 0, fmt.Errorf("not enough bytes to read label length")
		}

		length := int(buf[offset])
		if length > MAX_LABEL_LENGTH {
			return 0, fmt.Errorf("label length %d exceeds maximum of 63", length)
		}

		offset++

		return length, nil
	}

	readLabel := func(length int) (Label, error) {
		if len(buf) < offset+length {
			return "", fmt.Errorf("not enough bytes to read label")
		}

		label := string(buf[offset : offset+length])
		offset += length

		return Label(label), nil
	}

	for {
		labelLength, err := readLength()
		if err != nil {
			return 0, nil, err
		}

		if labelLength == 0 {
			break
		}

		label, err := readLabel(labelLength)
		if err != nil {
			return 0, nil, err
		}

		labels = append(labels, label)
	}

	return offset, &DomainName{
		Labels: labels,
	}, nil
}
