// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	maxNoteRunes = 2000
	listLimit    = 50
	// headerEmail is set by AppHub's sign-in proxy on every request. The
	// ingress strips any copy a client sends, so it can be trusted.
	headerEmail = "X-Auth-Request-Email"
)

// App serves the notes UI and API.
type App struct {
	store Store
	// devEmail stands in for the sign-in header when running locally, where
	// no proxy sets it. Empty in production.
	devEmail string
	log      *slog.Logger
}

// Routes returns the app's handler. State-changing requests from other
// origins are refused, since the browser sends the sign-in cookie with them.
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.withOwner(a.page))
	mux.HandleFunc("POST /notes", a.withOwner(a.createForm))
	mux.HandleFunc("POST /notes/{id}/delete", a.withOwner(a.deleteForm))
	mux.HandleFunc("GET /api/notes", a.withOwner(a.listJSON))
	mux.HandleFunc("POST /api/notes", a.withOwner(a.createJSON))
	mux.HandleFunc("DELETE /api/notes/{id}", a.withOwner(a.deleteJSON))
	return http.NewCrossOriginProtection().Handler(mux)
}

type ownerHandler func(w http.ResponseWriter, r *http.Request, owner string)

// withOwner resolves the signed-in user, refusing the request without one.
func (a *App) withOwner(next ownerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := strings.ToLower(strings.TrimSpace(r.Header.Get(headerEmail)))
		if owner == "" {
			owner = a.devEmail
		}
		if owner == "" {
			msg := "not signed in: the " + headerEmail + " header is missing"
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		next(w, r, owner)
	}
}

func validText(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", errors.New("note text is empty")
	}
	if utf8.RuneCountInString(text) > maxNoteRunes {
		return "", errors.New("note text is longer than 2000 characters")
	}
	return text, nil
}

func (a *App) fail(w http.ResponseWriter, r *http.Request, err error) {
	a.log.ErrorContext(r.Context(), "request failed",
		"method", r.Method, "path", r.URL.Path, "error", err)
	http.Error(w, "the notes table could not be reached; try again", http.StatusServiceUnavailable)
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notes</title>
<style>
body {
  font: 15px/1.5 system-ui, sans-serif; color: #1c1c1c;
  max-width: 640px; margin: 40px auto; padding: 0 16px;
}
header { display: flex; justify-content: space-between; align-items: baseline; }
.who { color: #666; font-size: 13px; }
form.new { display: flex; gap: 8px; margin: 20px 0; }
form.new input { flex: 1; padding: 8px; font: inherit; }
button { font: inherit; padding: 6px 12px; cursor: pointer; }
ul { list-style: none; padding: 0; }
li {
  display: flex; justify-content: space-between; gap: 12px;
  padding: 10px 0; border-top: 1px solid #e5e5e5;
}
li p { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
time { display: block; color: #888; font-size: 12px; }
.error { color: #b00020; }
</style>
</head>
<body>
<header><h1>Notes</h1><span class="who">{{.Owner}}</span></header>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form class="new" method="post" action="/notes">
<input name="text" maxlength="2000" placeholder="Write a note" required autofocus>
<button type="submit">Add</button>
</form>
<ul>
{{range .Notes}}<li>
<div><p>{{.Text}}</p><time>{{.CreatedAt.Format "Jan 2, 2006 15:04 MST"}}</time></div>
<form method="post" action="/notes/{{.ID}}/delete"><button type="submit">Delete</button></form>
</li>
{{else}}<li>No notes yet.</li>{{end}}
</ul>
</body>
</html>
`))

type pageData struct {
	Owner string
	Notes []Note
	Error string
}

func (a *App) render(w http.ResponseWriter, r *http.Request, owner string, status int, msg string) {
	notes, err := a.store.List(r.Context(), owner, listLimit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	data := pageData{Owner: owner, Notes: notes, Error: msg}
	if err := pageTemplate.Execute(w, data); err != nil {
		a.log.ErrorContext(r.Context(), "rendering page", "error", err)
	}
}

func (a *App) page(w http.ResponseWriter, r *http.Request, owner string) {
	a.render(w, r, owner, http.StatusOK, "")
}

func (a *App) createForm(w http.ResponseWriter, r *http.Request, owner string) {
	text, err := validText(r.FormValue("text"))
	if err != nil {
		a.render(w, r, owner, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := a.store.Create(r.Context(), owner, text); err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) deleteForm(w http.ResponseWriter, r *http.Request, owner string) {
	err := a.store.Delete(r.Context(), owner, r.PathValue("id"))
	if err != nil && !errors.Is(err, ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) listJSON(w http.ResponseWriter, r *http.Request, owner string) {
	notes, err := a.store.List(r.Context(), owner, listLimit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notes": notes})
}

func (a *App) createJSON(w http.ResponseWriter, r *http.Request, owner string) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `send JSON like {"text": "..."}`})
		return
	}
	text, err := validText(body.Text)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	n, err := a.store.Create(r.Context(), owner, text)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (a *App) deleteJSON(w http.ResponseWriter, r *http.Request, owner string) {
	err := a.store.Delete(r.Context(), owner, r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such note"})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
