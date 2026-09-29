// Package azidentity stands in for a cloud SDK from a vendor the substrate
// denylist does not name.
//
// It is the fourth substrate, and it is here because review planted exactly
// this and the denylist stayed green: a list of three vendors is blind to the
// next one, and adding a fourth entry would close this spelling while leaving
// the population defect where it was. What catches it is the import allowlist,
// which forbids everything it does not name.
package azidentity

// Symbol exists so an importer can reference something.
const Symbol = "azidentity"
