// Package winonly stands in for one AWS SDK package. Each import form gets its own
// package so a finding cannot be merged with another form's and read as
// covered when it was not.
package winonly

// Symbol exists so the non-blank import forms can reference something.
const Symbol = "winonly"
