// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"errors"

	"github.com/conductorone/apphub/modules"
)

// ErrNotConfigured is the deployment-configuration failure class, and it is
// [github.com/conductorone/apphub/modules.ErrNotConfigured] rather than a second
// sentinel meaning the same thing.
//
// Two names for one value is worse than one name: errors.Is cannot tell them
// apart, so every distinctness property stated over either of them is vacuous
// for the pair, and a caller that handles one silently handles the other
// without anybody deciding that it should. The framework already publishes this
// class with the meaning wanted here — an operator's problem, not fixable by
// sending different parameters — so this package uses it and does not restate
// it.
var ErrNotConfigured = modules.ErrNotConfigured

// ErrInvalidApplication reports that the stored application record cannot be
// deployed as written: two fields contradict each other, or one asks for
// something the record does not carry enough information to do.
//
// It is deliberately not the same class as a bad parameter. A caller who sent
// the wrong parameters can send different ones; an application whose record
// says it publishes a route and carries no hostname is fixed by editing the
// record, and telling the caller it was their mistake sends them to the wrong
// place.
var ErrInvalidApplication = errors.New("deploy: application record cannot be deployed as written")

// ErrSourceRefused reports that an application's source location was refused:
// it is not a well-formed HTTPS URL, or its host is not in
// [Config.AllowedSourceHosts].
//
// A separate class because it is the one failure here that an untrusted value
// can provoke. It is raised before the location reaches anything that would
// fetch it, and before it reaches a log line.
var ErrSourceRefused = errors.New("deploy: application source location refused")
