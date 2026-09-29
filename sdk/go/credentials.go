// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const clientID = "apphub-cli"

// ErrReauthenticationRequired means local credentials cannot safely authorize a
// request. Callers must log in again, not replay a potentially consumed refresh.
var ErrReauthenticationRequired = errors.New("AppHub login required; run apphub login --server <origin>")

type credential struct {
	Server       string    `json:"server"`
	Resource     string    `json:"resource"`
	ClientID     string    `json:"clientId"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	// Persisted before transmission: a crash or ambiguous response must never
	// cause another process to replay a potentially consumed refresh token.
	RefreshPending bool `json:"refreshPending,omitempty"`
}

type credentialFile struct {
	Current string                `json:"current"`
	Entries map[string]credential `json:"entries"`
}

type credentialStore struct {
	path string
	lock *flock.Flock
	data credentialFile
}

func credentialKey(server string) string { return server + "\n" + server + "/api\n" + clientID }

func privatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("unsafe credential storage path: %s", path)
	}
	return securePermissions(path, directory)
}

func openCredentials(ctx context.Context) (*credentialStore, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate user config: %w", err)
	}
	dir := filepath.Join(base, "apphub")
	if err := privatePath(dir, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := privatePath(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "credentials.json")
	lockPath := filepath.Join(dir, "credentials.lock")
	if err := privatePath(lockPath, false); err != nil {
		return nil, err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0600))
	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("lock credentials: %w", err)
	}
	if !locked {
		return nil, errors.New("could not lock credentials")
	}
	s := &credentialStore{path: path, lock: lock, data: credentialFile{Entries: map[string]credential{}}}
	if err := privatePath(path, false); err != nil {
		s.close()
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- Fixed credentials.json beneath the OS-user config directory; privatePath rejects symlinks and enforces private permissions under the credential lock.
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		s.close()
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		s.close()
		return nil, err
	}
	if len(b) > 1<<20 {
		s.close()
		return nil, errors.New("credential file exceeds size limit")
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		s.close()
		return nil, errors.New("invalid credential file; refusing to overwrite it")
	}
	if s.data.Entries == nil {
		s.data.Entries = map[string]credential{}
	}
	return s, nil
}

func (s *credentialStore) close() { _ = s.lock.Close() }

func (s *credentialStore) save() (err error) {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".credentials-*")
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := os.Remove(f.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, fmt.Errorf("remove temporary credential file: %w", removeErr))
		}
	}()
	if err := f.Chmod(0600); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := f.Write(b); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The separate lock inode remains stable across atomic file replacement.
	return replaceCredentials(f.Name(), s.path)
}

func (s *credentialStore) remove(key string) error {
	delete(s.data.Entries, key)
	if s.data.Current == key {
		s.data.Current = ""
	}
	return s.save()
}

// FromContext loads the last successfully selected, server-bound login.
func FromContext() (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := openCredentials(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	entry, ok := s.data.Entries[s.data.Current]
	if !ok {
		return nil, ErrReauthenticationRequired
	}
	if entry.RefreshPending || entry.RefreshToken == "" {
		return nil, errors.Join(ErrReauthenticationRequired, s.remove(s.data.Current))
	}
	c, err := NewClient(entry.Server)
	if err != nil {
		return nil, err
	}
	if !c.matches(entry) || s.data.Current != credentialKey(c.Server) {
		return nil, ErrReauthenticationRequired
	}
	return c, nil
}

func (c *Client) matches(entry credential) bool {
	return entry.Server == c.origin && entry.Resource == c.origin+"/api" && entry.ClientID == clientID
}

func (c *Client) accessToken(ctx context.Context, rejected string) (string, error) {
	s, err := openCredentials(ctx)
	if err != nil {
		return "", err
	}
	defer s.close()
	key := credentialKey(c.origin)
	entry, ok := s.data.Entries[key]
	if !ok {
		return "", ErrReauthenticationRequired
	}
	if !c.matches(entry) || entry.RefreshPending || entry.RefreshToken == "" {
		return "", errors.Join(ErrReauthenticationRequired, s.remove(key))
	}
	if entry.AccessToken != "" && time.Until(entry.ExpiresAt) > time.Minute && (rejected == "" || entry.AccessToken != rejected) {
		return entry.AccessToken, nil
	}
	// Write ahead of the request so termination at any point cannot replay it.
	entry.RefreshPending = true
	s.data.Entries[key] = entry
	if err := s.save(); err != nil {
		return "", fmt.Errorf("record refresh intent: %w", err)
	}
	tok, err := c.postToken(ctx, refreshForm(entry.RefreshToken, c.origin+"/api"))
	if err != nil {
		return "", errors.Join(ErrReauthenticationRequired, s.remove(key))
	}
	entry.AccessToken, entry.RefreshToken = tok.AccessToken, tok.RefreshToken
	entry.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	entry.RefreshPending = false
	s.data.Entries[key] = entry
	if err := s.save(); err != nil {
		return "", errors.Join(ErrReauthenticationRequired, fmt.Errorf("persist rotated credentials: %w", err))
	}
	return entry.AccessToken, nil
}

func (c *Client) invalidateToken(ctx context.Context, rejected string) error {
	s, err := openCredentials(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	key := credentialKey(c.origin)
	// Another process may already have installed a newer credential.
	if entry, ok := s.data.Entries[key]; ok && entry.AccessToken == rejected {
		return s.remove(key)
	}
	return nil
}

// Logout revokes the delegated OAuth family before removing the local record.
// A revocation failure retains credentials so the user can retry.
func (c *Client) Logout(ctx context.Context) error {
	if err := c.checkServer(); err != nil {
		return err
	}
	s, err := openCredentials(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	key := credentialKey(c.origin)
	entry, ok := s.data.Entries[key]
	if !ok {
		return nil
	}
	if !c.matches(entry) {
		return ErrReauthenticationRequired
	}
	if err := c.revoke(ctx, entry.RefreshToken); err != nil {
		return err
	}
	return s.remove(key)
}
