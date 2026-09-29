package tested

import (
	"testing"

	_ "example.com/unionwrapper/forbidden/intest"
)

func TestName(t *testing.T) {
	if Name == "" {
		t.Fatal("empty")
	}
}
