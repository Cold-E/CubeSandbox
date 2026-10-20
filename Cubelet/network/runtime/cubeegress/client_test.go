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

// TestConnectionRefusedReturnsError confirms the client surfaces the
// refusal error (the adapter, not the client, decides whether to
// downgrade it). Configured() stays true so the create/push path keeps
// retrying through a sidecar restart in the K8s chart.
func TestConnectionRefusedReturnsError(t *testing.T) {
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

	err = c.DeletePolicy(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatalf("DeletePolicy returned nil on connection refused, want error")
	}
	if !IsConnectionRefused(err) {
		t.Fatalf("DeletePolicy err = %v, want a connection-refused error", err)
	}
	// Crucially, the client does NOT self-disable: a K8s sidecar restart
	// also refuses the port momentarily, and the create path must keep
	// retrying through it.
	if !c.Configured() {
		t.Fatalf("Configured() = false after connection refused, want true (client must NOT self-disable)")
	}
}

// TestServer5xxReturnsError ensures a live sidecar returning 5xx keeps
// the error retryable (neither downgraded nor self-disabled).
func TestServer5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	err := c.DeletePolicy(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatalf("DeletePolicy returned nil on 5xx, want error")
	}
	if IsConnectionRefused(err) {
		t.Fatalf("5xx classified as connection-refused, want false")
	}
	if !c.Configured() {
		t.Fatalf("Configured() = false after 5xx, want true")
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
// the sidecar may be slow (but present) must not be classified as a
// refusal — that path stays retryable.
func TestContextTimeoutNotClassifiedAsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, 50*time.Millisecond)
	err := c.DeletePolicy(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatalf("DeletePolicy returned nil on timeout, want error")
	}
	if IsConnectionRefused(err) {
		t.Fatalf("timeout classified as connection-refused, want false")
	}
}

// TestIsConnectionRefusedClassifier sanity-checks the classifier against
// a real ECONNREFUSED dial error so the string fallback never silently
// drifts across platforms (Linux "connection refused" / Windows
// "actively refused it").
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
	if !IsConnectionRefused(dialErr) {
		t.Fatalf("IsConnectionRefused(%v) = false, want true", dialErr)
	}
	if IsConnectionRefused(nil) {
		t.Fatalf("IsConnectionRefused(nil) = true, want false")
	}
	if IsConnectionRefused(errors.New("some other error")) {
		t.Fatalf("IsConnectionRefused(other) = true, want false")
	}
}
