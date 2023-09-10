package guid

import (
	"crypto/rand"
	"fmt"
)

type GUID [16]byte

func NewGUID() GUID {
	guid := new(GUID)

	_, err := rand.Read(guid[:])
	if err != nil {
		panic(err)
	}

	guid[6] = (guid[6] & 0x0f) | 0x40
	guid[8] = (guid[8] & 0x3f) | 0x80

	return *guid
}

func (guid GUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		guid[0:4], guid[4:6], guid[6:8], guid[8:10], guid[10:])
}
