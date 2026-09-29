// Package aws stands in for the AWS provider. It is not a subject of the fence,
// so its own SDK imports are fine; what is not fine is the deploy module
// reaching them through it.
package aws

import "github.com/aws/aws-sdk-go-v2/viaprovider"

// Symbol exists so an importer can reference something.
const Symbol = viaprovider.Symbol
