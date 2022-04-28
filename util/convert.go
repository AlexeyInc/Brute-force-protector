package util

import "bytes"

func ByteRowsToStrings(fileData []byte) (result []string) {
	rows := bytes.Split(fileData, []byte{'\n'})
	for _, w := range rows {
		result = append(result, string(w))
	}
	return
}
