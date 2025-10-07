package certhelper

import (
	"testing"
)

func TestCSRCreate(t *testing.T) {

	key := MustGetPrivKey("/tmp/testkey.pem")
	_, err := GenCSR(key)
	if err != nil {
		t.FailNow()
	}

}
