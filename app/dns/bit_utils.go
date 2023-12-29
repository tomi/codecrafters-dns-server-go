package dns

import (
	"encoding/binary"
	"fmt"
)

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

func uint16FromBytes(buf []byte) (uint16, error) {
	if len(buf) != 2 {
		return 0, fmt.Errorf("expected 2 bytes, got %d", len(buf))
	}

	return binary.BigEndian.Uint16(buf), nil
}
