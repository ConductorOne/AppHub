// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghappkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/conductorone/apphub/credentials"
)

// LocalConfig names a local file the admin-managed GitHub App private key is
// stored under, in place of AWS SSM Parameter Store.
//
// It exists only for local development -- serverconfig.validateGitHubAppAdmin
// requires it never coexist with SSM in the same configuration -- and stores
// the key in cleartext JSON, restricted to file mode 0600. That is an
// acceptable trade on a developer's own machine; it is not a substitute for
// SSM in any deployment another person or process can reach. See the package
// doc for why Store and Reader stay split even here.
type LocalConfig struct {
	// Path is the file the key is read from and written to. Required. Its
	// parent directory must already exist.
	Path string
}

func (c LocalConfig) validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("%w: path is required", ErrConfiguration)
	}
	return nil
}

// localFile is the on-disk shape. A struct, not a bare string, so a future
// field (rotation metadata, say) does not require a format migration.
type localFile struct {
	PEM string `json:"pem"`
}

type localStore struct {
	mu   sync.Mutex
	path string
}

// NewLocalStore returns a Store backed by a local file. It performs no I/O of
// its own; the file is created on first Put.
func NewLocalStore(cfg LocalConfig) (Store, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &localStore{path: cfg.Path}, nil
}

func (s *localStore) Put(_ context.Context, key credentials.Secret) error {
	pem := credentials.Reveal(key)
	if strings.TrimSpace(pem) == "" {
		return fmt.Errorf("%w: key is required", ErrInvalidKey)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(localFile{PEM: pem})
	if err != nil {
		return fmt.Errorf("%w: encoding the key failed", ErrUnavailable)
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("%w: writing the local key file failed", ErrUnavailable)
	}
	return nil
}

func (s *localStore) Exists(_ context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := os.Stat(s.path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("%w: checking the local key file failed", ErrUnavailable)
	}
}

func (s *localStore) Delete(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: deleting the local key file failed", ErrUnavailable)
	}
	return nil
}

type localReader struct {
	path string
}

// NewLocalReader returns a Reader backed by the same local file NewLocalStore writes.
func NewLocalReader(cfg LocalConfig) (Reader, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &localReader{path: cfg.Path}, nil
}

func (r *localReader) Get(_ context.Context) (credentials.Secret, error) {
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return credentials.Secret{}, ErrNotFound
	}
	if err != nil {
		return credentials.Secret{}, fmt.Errorf("%w: reading the local key file failed", ErrUnavailable)
	}
	var f localFile
	if json.Unmarshal(data, &f) != nil || strings.TrimSpace(f.PEM) == "" {
		return credentials.Secret{}, ErrNotFound
	}
	return credentials.NewSecret(f.PEM), nil
}

var (
	_ Store  = (*localStore)(nil)
	_ Reader = (*localReader)(nil)
)
