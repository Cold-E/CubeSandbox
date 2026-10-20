// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package cubeegress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestConfiguredEmptyAdminURL covers the explicit dev-mode path: an
// empty admin URL means Configured() is false and every method returns
// ErrNotConfigured without any network activity.
func TestConfiguredEmptyAdminURL(t *testing.T) {
	c := New("", 0)
	if c.Configured() {
		t.Fatalf("Configured() = true for empty adminURL, want false")
	}
	if err := c.DeletePolicy(context.Background(), "10.0.0.1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("DeletePolicy err = %v, want ErrNotConfigured", err)
	}
}

// TestConnectionRefusedMarksUnreachable is the core bare-metal
// graceful-degrade test: a configured client whose admin endpoint is
// not listening (connection refused) must mark itself unreachable, so
// subsequent Configured() returns false and callers no-op instead of
// retrying against a dead port forever.
func TestConnectionRefusedMarksUnreachable(t *testing.T) {
	// Pick a port that is effectively guaranteed to be closed: bind
	// a listener, capture its address, close it, then dial it. On a
	// quiet loopback this yields ECONNREFUSED deterministically.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot allocate loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	c := New("http://"+addr, time.Second)
	if !c.Configured() {
		t.Fatalf("Configured() = false before first call, want true")
	}

	// First DeletePolicy hits connection-refused and marks unreachable.
	err = c.DeletePolicy(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatalf("DeletePolicy returned nil on connection refused, want error")
	}
	if !isConnectionRefused(err) {
		t.Fatalf("DeletePolicy err = %v, want a connection-refused error", err)
	}
	if c.Configured() {
		t.Fatalf("Configured() = true after connection refused, want false (client should self-disable)")
	}

	// Subsequent calls must short-circuit via Configured() and return
	// ErrNotConfigured without touching the network again.
	if err := c.DeletePolicy(context.Background(), "10.0.0.1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("second DeletePolicy err = %v, want ErrNotConfigured after self-disable", err)
	}
}

// TestServer5xxDoesNotMarkUnreachable ensures a live sidecar returning
// 5xx is NOT treated as absent — that path stays retryable so a
// temporary OpenResty hiccup doesn't silently drop egress policy.
func TestServer5xxDoesNotMarkUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	_ = c.DeletePolicy(context.Background(), "10.0.0.1")
	if !c.Configured() {
		t.Fatalf("Configured() = false after 5xx, want true (transient errors must not self-disable)")
	}
}

// TestServer2xxKeepsConfigured is the happy path: a live sidecar
// returning 2xx keeps the client configured.
func TestServer2xxKeepsConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	if err := c.DeletePolicy(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("DeletePolicy err = %v, want nil", err)
	}
	if !c.Configured() {
		t.Fatalf("Configured() = false after 2xx, want true")
	}
}

// TestContextTimeoutDoesNotMarkUnreachable: a deadline exceeded while
// the sidecar may be slow (but present) must not be treated as absence.
func TestContextTimeoutDoesNotMarkUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep past the client timeout; the context will cancel.
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, 50*time.Millisecond)
	_ = c.DeletePolicy(context.Background(), "10.0.0.1")
	if !c.Configured() {
		t.Fatalf("Configured() = false after timeout, want true (timeout must not self-disable)")
	}
}

// TestIsConnectionRefusedClassifier sanity-checks the classifier against
// a real ECONNREFUSED dial error so the string fallback never silently
// drifts.
func TestIsConnectionRefusedClassifier(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot allocate loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, dialErr := net.Dial("tcp", addr)
	if dialErr == nil {
		t.Skip("dial to closed port succeeded; cannot test classifier")
	}
	if !isConnectionRefused(dialErr) {
		t.Fatalf("isConnectionRefused(%v) = false, want true", dialErr)
	}
}
