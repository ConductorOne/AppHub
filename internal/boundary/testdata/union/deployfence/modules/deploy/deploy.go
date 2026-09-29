// Package deploy is the subject of the fence. Every import form below is a way
// somebody has actually got past an import check on this project.
package deploy

import (
	// The standard library, which the import allowlist permits without naming.
	// It is here as the control for that: a rule that flagged it would forbid
	// everything and pass every table asserting things are caught.
	"strings"

	_ "github.com/aws/aws-sdk-go-v2/blank"
	"github.com/aws/aws-sdk-go-v2/direct"
	. "github.com/aws/aws-sdk-go-v2/dotted"

	alias "github.com/aws/aws-sdk-go-v2/aliased"

	// A substrate the denylist does not name. Only the import allowlist sees
	// this one.
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	// And one whose module path has no dot in its first element, which the
	// allowlist's membership test used to read as standard library.
	_ "cloud/sdk/azidentity"

	"github.com/conductorone/apphub/compute"
	_ "github.com/conductorone/apphub/compute/aws"
	"k8s.io/api/core"
)

// Used references every non-blank form so the file compiles.
var Used = strings.ToUpper(direct.Symbol + alias.Symbol + Symbol + core.Symbol + compute.Symbol)
