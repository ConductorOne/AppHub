// Package cgocall is invisible to every concrete build configuration this
// checker runs, because they all set CGO_ENABLED=0 and a file importing "C" is
// then excluded. The union reads it anyway, which is the entire thesis.
package cgocall

/*
#include <stdlib.h>
*/
import "C"

import _ "example.com/unionwrapper/forbidden"

var _ = C.malloc
