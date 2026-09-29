package clean

import (
	"testing"

	_ "example.com/unionwrapper/forbidden"
)

func TestName(t *testing.T) {
	if Name == "" {
		t.Fatal("empty")
	}
}
