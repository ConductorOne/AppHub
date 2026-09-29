// Package clean has no denied import in its production source. Its test file
// does, and a dependency's tests are not part of any build or test of the main
// module.
package clean

// Name exists so the package has content.
const Name = "clean"
