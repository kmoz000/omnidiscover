package omnidiscover

import (
	"slices"

	"github.com/kmoz000/omnidiscover/pkg/utils"
)

func copyBytes(dst, src []byte) []byte {
	return utils.CopyBytes(dst, src)
}

func cleanText(b []byte) []byte {
	return utils.CleanText(b)
}

func appendUniqueMAC(dst []MAC, value MAC) []MAC {
	if slices.Contains(dst, value) {
		return dst
	}
	return append(dst, value)
}
