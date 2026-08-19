package omnidiscover

import "github.com/kmoz000/omnidiscover/pkg/utils"

func copyBytes(dst, src []byte) []byte {
	return utils.CopyBytes(dst, src)
}

func cleanText(b []byte) []byte {
	return utils.CleanText(b)
}

func appendUniqueMAC(dst []MAC, value MAC) []MAC {
	for _, v := range dst {
		if v == value {
			return dst
		}
	}
	return append(dst, value)
}
