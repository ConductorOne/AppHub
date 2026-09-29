// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory Store standing in for DynamoDB.
type memStore struct {
	mu    sync.Mutex
	notes map[string][]Note
	fail  error
	next  int
}

func newMemStore() *memStore { return &memStore{notes: map[string][]Note{}} }

func (m *memStore) List(_ context.Context, owner string, limit int32) ([]Note, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	out := slices.Clone(m.notes[owner])
	slices.Reverse(out)
	return out[:min(int(limit), len(out))], nil
}

func (m *memStore) Create(_ context.Context, owner, text string) (Note, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return Note{}, m.fail
	}
	m.next++
	n := Note{ID: string(rune('a' + m.next)), Text: text, CreatedAt: time.Now().UTC()}
	m.notes[owner] = append(m.notes[owner], n)
	return n, nil
}

func (m *memStore) Delete(_ context.Context, owner, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	i := slices.IndexFunc(m.notes[owner], func(n Note) bool { return n.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	m.notes[owner] = slices.Delete(m.notes[owner], i, i+1)
	return nil
}

func newTestApp(store Store) http.Handler { return newDevApp(store, "") }

func newDevApp(store Store, devEmail string) http.Handler {
	app := &App{store: store, devEmail: devEmail, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return app.Routes()
}

// send serves one request as email; an empty email sends no sign-in header.
func send(h http.Handler, req *http.Request, email string) *httptest.ResponseRecorder {
	if email != "" {
		req.Header.Set(headerEmail, email)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func get(h http.Handler, target, email string) *httptest.ResponseRecorder {
	return send(h, httptest.NewRequest(http.MethodGet, target, nil), email)
}

func del(h http.Handler, target, email string) *httptest.ResponseRecorder {
	return send(h, httptest.NewRequest(http.MethodDelete, target, nil), email)
}

func postJSON(h http.Handler, target, email, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return send(h, req, email)
}

func postForm(h http.Handler, target, email string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(h, req, email)
}

func TestRequestsWithoutSignInAreRefused(t *testing.T) {
	h := newTestApp(newMemStore())
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"page":   get(h, "/", ""),
		"list":   get(h, "/api/notes", ""),
		"create": postJSON(h, "/api/notes", "", `{"text":"x"}`),
		"delete": del(h, "/api/notes/x", ""),
	} {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d; want 401", name, rec.Code)
		}
	}
}

func TestDevEmailStandsInForTheHeader(t *testing.T) {
	store := newMemStore()
	h := newDevApp(store, "dev@example.com")
	if rec := postJSON(h, "/api/notes", "", `{"text":"local"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d; want 201", rec.Code)
	}
	if len(store.notes["dev@example.com"]) != 1 {
		t.Fatalf("notes = %v; want one owned by the dev email", store.notes)
	}
}

func TestNotesAreScopedToTheSignedInUser(t *testing.T) {
	store := newMemStore()
	h := newTestApp(store)
	rec := postJSON(h, "/api/notes", "Alice@Example.com", `{"text":"  buy milk  "}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s; want 201", rec.Code, rec.Body)
	}
	var created Note
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Text != "buy milk" {
		t.Fatalf("created = %+v, %v; want trimmed text", created, err)
	}

	var list struct{ Notes []Note }
	rec = get(h, "/api/notes", "alice@example.com")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Notes) != 1 {
		t.Fatalf("alice's list = %s, %v; want her one note", rec.Body, err)
	}
	rec = get(h, "/api/notes", "bob@example.com")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Notes) != 0 {
		t.Fatalf("bob's list = %s, %v; want empty", rec.Body, err)
	}
	if rec := del(h, "/api/notes/"+created.ID, "bob@example.com"); rec.Code != http.StatusNotFound {
		t.Fatalf("bob deleting alice's note = %d; want 404", rec.Code)
	}
	rec = del(h, "/api/notes/"+created.ID, "alice@example.com")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("alice deleting her note = %d; want 204", rec.Code)
	}
}

func TestInvalidNotesAreRejected(t *testing.T) {
	h := newTestApp(newMemStore())
	for name, body := range map[string]string{
		"empty":     `{"text":"   "}`,
		"too long":  `{"text":"` + strings.Repeat("é", maxNoteRunes+1) + `"}`,
		"malformed": `{"text":`,
	} {
		if rec := postJSON(h, "/api/notes", "a@example.com", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d; want 400", name, rec.Code)
		}
	}
	rec := postForm(h, "/notes", "a@example.com", url.Values{"text": {""}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty form note = %d; want 400", rec.Code)
	}
}

func TestFormFlowCreatesListsAndDeletes(t *testing.T) {
	store := newMemStore()
	h := newTestApp(store)
	rec := postForm(h, "/notes", "a@example.com", url.Values{"text": {"<script>x</script>"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form create = %d; want 303", rec.Code)
	}
	rec = get(h, "/", "a@example.com")
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;x&lt;/script&gt;") {
		t.Fatalf("page does not show the escaped note:\n%s", rec.Body)
	}
	id := store.notes["a@example.com"][0].ID
	rec = postForm(h, "/notes/"+id+"/delete", "a@example.com", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form delete = %d; want 303", rec.Code)
	}
	if len(store.notes["a@example.com"]) != 0 {
		t.Fatal("note was not deleted")
	}
}

func TestCrossOriginWritesAreRefused(t *testing.T) {
	store := newMemStore()
	h := newTestApp(store)
	req := httptest.NewRequest(http.MethodPost, "/notes", strings.NewReader("text=hi"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := send(h, req, "a@example.com")
	if rec.Code != http.StatusForbidden || len(store.notes) != 0 {
		t.Fatalf("cross-site POST = %d, notes %v; want 403, nothing stored", rec.Code, store.notes)
	}
}

func TestStoreFailureIsReportedWithoutDetail(t *testing.T) {
	store := newMemStore()
	store.fail = errors.New("AccessDeniedException: secret internals")
	rec := get(newTestApp(store), "/api/notes", "a@example.com")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("store failure = %d %q; want 503 without the error text", rec.Code, rec.Body)
	}
}
