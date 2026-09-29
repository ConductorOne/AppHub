// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package cookiestrip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestForwardAuthThenStrip(t *testing.T) {
	appCookies := make(chan []string, 1)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appCookies <- r.Header.Values("Cookie")
		w.WriteHeader(http.StatusNoContent)
	})
	strip, err := New(context.Background(), app, &Config{Enabled: true}, "strip-sso")
	if err != nil {
		t.Fatal(err)
	}
	// Traefik calls ForwardAuth before the strip middleware. Its auth request
	// sees the unmodified session; the application sees only its own cookies.
	auth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("Cookie"); !reflect.DeepEqual(got, []string{
			"app=first; \t_oauth2_proxy=secret; _oauth2_proxy_0=part0; _oauth2_proxy_1=part1; other=two",
			"_OAUTH2_PROXY_CSRF=csrf; third=three; _Oauth2_Proxy=duplicate; fourth=\"quoted=value\"",
		}) {
			t.Errorf("ForwardAuth cookie headers = %q", got)
		}
		strip.ServeHTTP(w, r)
	})
	server := httptest.NewServer(auth)
	defer server.Close()
	r, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Add("Cookie", "app=first; \t_oauth2_proxy=secret; _oauth2_proxy_0=part0; _oauth2_proxy_1=part1; other=two")
	r.Header.Add("Cookie", "_OAUTH2_PROXY_CSRF=csrf; third=three; _Oauth2_Proxy=duplicate; fourth=\"quoted=value\"")
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got, want := <-appCookies, []string{"app=first; other=two", "third=three; fourth=\"quoted=value\""}; !reflect.DeepEqual(got, want) {
		t.Fatalf("application Cookie headers = %q, want %q", got, want)
	}
}

func TestRejectMalformedCookieBeforeApplication(t *testing.T) {
	for _, header := range []string{
		"app=ok; _oauth2_proxy=secret; broken",
		"app=ok; ; _oauth2_proxy=secret",
		"app=ok; _oauth2_proxy=secret; bad name=x",
		"app=ok; _oauth2_proxy=secret; bad=unquoted value",
		"app=ok; _oauth2_proxy=secret; other=\"unterminated",
		"app=ok; _oauth2_proxy=secret; =empty-name",
		"app=ok; _oauth2_proxy=secret; other=bad\x7fvalue",
	} {
		t.Run(header, func(t *testing.T) {
			called := false
			strip, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}), &Config{Enabled: true}, "strip-sso")
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Add("Cookie", "valid=one")
			r.Header.Add("Cookie", header)
			w := httptest.NewRecorder()
			strip.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || called {
				t.Fatalf("status=%d, upstream called=%t", w.Code, called)
			}
		})
	}
}

func TestEmptyValuesAndNonSessionNames(t *testing.T) {
	got, err := filter("app=; _oauth2_proxy=; _oauth2_proxy_123=chunk; _oauth2_proxyOther=kept; x=one=two")
	if err != nil {
		t.Fatal(err)
	}
	if want := "app=; _oauth2_proxyOther=kept; x=one=two"; got != want {
		t.Fatalf("filtered Cookie=%q, want %q", got, want)
	}
}

func TestSessionOnlyRemovesCookieHeader(t *testing.T) {
	strip, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("Cookie"); len(got) != 0 {
			t.Errorf("shared session leaked upstream: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}), &Config{Enabled: true}, "strip-sso")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Cookie", "_oauth2_proxy=token; _oauth2_proxy_0=part")
	w := httptest.NewRecorder()
	strip.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestDisabledPluginFailsClosed(t *testing.T) {
	if _, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream called")
	}), CreateConfig(), "strip-sso"); err == nil {
		t.Fatal("missing enabled label must reject middleware")
	}
}
