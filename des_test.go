package sec

import (
	"strings"
	"testing"
)

var testKey = "asdlfkajg1028412035ulj.c,xmop830"
var AESClient = NewAES(testKey)

func TestAESEncryptAndDecrypt(test *testing.T) {
	var testStr = "abc=123"
	test.Log("TestStr: ", testStr)
	enBytes, err := AESClient.Encrypt([]byte(testStr))
	if err != nil {
		test.Errorf("Encrypt Error:%v", err)
	}
	enString := ToBase64(enBytes)
	test.Log("Encrypt: ", enString)
	enBytes, _ = ToBytes(enString)
	deBytes, _ := AESClient.Decrypt(enBytes)
	test.Log("Decrypt: ", string(deBytes))
	// 加密时需要给字符串补位，所以会加上空白字符
	test.Log("Decrypt Len: ", len(string(deBytes)), len(testStr))
	deStr := strings.Trim(string(deBytes), " \n\t")
	test.Log("Trim Len: ", len(deStr), len(testStr))
	if deStr != testStr {
		test.Error("AES Decrypt string can not match Encrypt string")
	}
}
