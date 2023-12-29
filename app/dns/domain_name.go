package dns

import "fmt"

type Label string

type DomainName struct {
	Labels []Label
}

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
		if labelLength > 63 {
			return nil, fmt.Errorf("label length %d exceeds maximum of 63", labelLength)
		}

		buf = append(buf, byte(labelLength))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0)

	return buf, nil
}
