// Package deploy looks clean on the build target CI happens to run.
package deploy

import "fmt"

// Hello exists so the package has content.
func Hello() string { return fmt.Sprint("hello") }
