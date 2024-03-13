package criptus

import "log"

var BaseSpecialSign = "!@a%$bc.de,l%$fgqweruriskn&#@xl784zm321apgiw"
var BaseSpecialSignLength = len(BaseSpecialSign)

func formatSpecialSign(specialSign, key string, kind any) string {
	var length int
	var name string

	switch kind.(type) {
	case AesKeyType:
		length = kind.(AesKeyType).Length()
		name = kind.(AesKeyType).String()
	case DesKeyType:
		length = kind.(DesKeyType).Length()
		name = kind.(DesKeyType).String()
	case TripleKeyType:
		length = kind.(TripleKeyType).Length()
		name = kind.(TripleKeyType).String()
	}

	specialSignLength := len(specialSign)
	if specialSignLength+len(key) < length {
		log.Printf("【WARN】 %s the length of specialSign and key less %d\n", name, length)
		if specialSignLength%2 == 0 {
			specialSign += BaseSpecialSign[:length-len(specialSign)]
		} else {
			specialSign += BaseSpecialSign[BaseSpecialSignLength-length:]
		}
	}
	if specialSignLength > length {
		if specialSignLength%2 == 0 {
			specialSign = specialSign[:length+1]
		} else {
			specialSign = specialSign[len(specialSign)-length:]
		}
	}
	return specialSign
}
