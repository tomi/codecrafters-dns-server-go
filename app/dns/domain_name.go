package dns

import (
	"encoding/binary"
	"fmt"
)

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

func deserializeDomainName(buf []byte, offset int) (int, *DomainName, error) {
	bytesRead, labels, err := deSerializeLabels(buf, offset)
	if err != nil {
		return 0, nil, err
	}

	return bytesRead, &DomainName{
		Labels: labels,
	}, nil
}

func deSerializeLabels(buf []byte, offset int) (int, []Label, error) {
	startOffset := offset
	labels := make([]Label, 0)

	for {
		if isPointer(buf, offset) {
			pointerOffset, err := readPointer(buf, offset)
			if err != nil {
				return 0, nil, err
			}

			offset += 2

			_, pointedLabels, err := deSerializeLabels(buf, pointerOffset)
			if err != nil {
				return 0, nil, err
			}

			labels = append(labels, pointedLabels...)
			break
		}

		// Is a normal label with length prefix
		labelLength, err := readLength(buf, offset)
		if err != nil {
			return 0, nil, err
		}

		offset += 1

		if labelLength == 0 {
			break
		}

		label, err := readLabel(buf, offset, labelLength)
		if err != nil {
			return 0, nil, err
		}

		offset += labelLength
		labels = append(labels, label)
	}

	return offset - startOffset, labels, nil
}

func isPointer(buf []byte, offset int) bool {
	if len(buf) < offset+1 {
		return false
	}

	// Pointer takes the form of a two octet sequence:
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// | 1  1|                OFFSET                   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// 1100 0000 == 0xC0
	isPointer := buf[offset]&0xC0 == 0xC0

	return isPointer
}

func readPointer(buf []byte, offset int) (int, error) {
	if len(buf) < offset+2 {
		return 0, fmt.Errorf("not enough bytes to read pointer offset")
	}

	// Pointer takes the form of a two octet sequence:
	// Clear the two high order bits
	// 0011 1111 1111 1111 == 0x3FFF
	asUint16 := binary.BigEndian.Uint16(buf[offset : offset+2])
	pointerOffset := int(asUint16 & 0x3FFF)

	return int(pointerOffset), nil
}

func readLength(buf []byte, offset int) (int, error) {
	if len(buf) < offset+1 {
		return 0, fmt.Errorf("not enough bytes to read label length")
	}

	length := int(buf[offset])
	if length > MAX_LABEL_LENGTH {
		return 0, fmt.Errorf("label length %d exceeds maximum of 63", length)
	}

	return length, nil
}

func readLabel(buf []byte, offset int, length int) (Label, error) {
	if len(buf) < offset+length {
		return "", fmt.Errorf("not enough bytes to read label")
	}

	label := string(buf[offset : offset+length])

	return Label(label), nil
}
