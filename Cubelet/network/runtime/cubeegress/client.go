// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package cubeegress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// DefaultPushTimeout is the per-call timeout when no override is supplied.
// Conservative bound for a loopback HTTP call against an OpenResty admin
// listener that does cheap shared-dict operations; if it ever exceeds
// this, something is genuinely wrong.
const DefaultPushTimeout = 2 * time.Second

// ErrNotConfigured indicates the client has no admin URL configured. The
// callers (push site at EnsureNetwork, delete site at ReleaseNetwork)
// treat this as "skip silently" — preserves the existing dev-mode where
// CubeEgress simply isn't deployed.
var ErrNotConfigured = errors.New("cubeegress: admin URL not configured")

// PermanentError wraps a 4xx response from the admin API. The retry
// loop should NOT retry these — the request is malformed and a re-PUT
// of the same body will fail the same way. Operators learn about it via
// the WARN log emitted at the call site.
type PermanentError struct {
	Status int
	Body   string
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("cubeegress: %d %s", e.Status, e.Body)
}

// IsPermanent reports whether err is a PermanentError. The retry loop
// uses this to short-circuit.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// IsNotFound reports whether err is a 404 response from the admin API.
func IsNotFound(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe) && pe.Status == http.StatusNotFound
}

// Client speaks the subset of CubeEgress's /admin/v1 we need:
// PUT /policies/<ip> (full replace), DELETE /policies/<ip>, and
// GET /policies/<ip> for delete verification.
//
// Loopback only: by convention adminURL is http://127.0.0.1:9091, so
// this connects over a localhost TCP socket. No keepalive pool is
// shared across sandboxes — egress-policy mutations are infrequent
// (one per sandbox lifetime) and the cost of a fresh connection is
// noise next to tap allocation.
type Client struct {
	adminURL string
	timeout  time.Duration
	httpc    *http.Client
}

// New returns a Client configured to talk to adminURL with the given
// per-call timeout. Empty adminURL is allowed; methods on the returned
// client return ErrNotConfigured so the caller can detect dev mode.
func New(adminURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultPushTimeout
	}
	return &Client{
		adminURL: strings.TrimRight(adminURL, "/"),
		timeout:  timeout,
		httpc: &http.Client{
			Timeout: timeout,
			// No transport tweaks: the default http.Transport pools
			// idle conns and is fine for loopback. We bound a single
			// call via the per-request context.
		},
	}
}

// Configured reports whether the client has an admin URL. Use it before
// PutPolicy/DeletePolicy when the caller wants to no-op silently rather
// than receive ErrNotConfigured.
func (c *Client) Configured() bool {
	return c != nil && c.adminURL != ""
}

// IsLoopback reports whether the admin URL points at a loopback address
// (127.0.0.0/8, ::1, or "localhost"). The release-path connection-refused
// downgrade is gated on this: a refused loopback dial is strong evidence
// the colocated sidecar is absent and its in-memory policy store is gone,
// so the IP can be safely reused. A refusal on a non-loopback URL
// (proxy/LB/remote admin listener) does NOT prove the policy store is
// gone — the sidecar may be alive elsewhere and still hold the previous
// sandbox's policy/secrets — so the downgrade must not fire there.
func (c *Client) IsLoopback() bool {
	if c == nil || c.adminURL == "" {
		return false
	}
	u, err := url.Parse(c.adminURL)
	if err != nil {
		return false
	}
	// u.Hostname() preserves the raw host verbatim — no lowercasing, and
	// a trailing dot (FQDN form like "localhost.") is kept. DNS is
	// case-insensitive and ignores the trailing dot, so a config of
	// http://LOCALHOST:9091 or http://localhost.:9091 still dials the
	// sidecar. Without normalization the named-form check below would
	// miss those, the release-path downgrade would never fire, and the
	// bare-metal stall this PR fixes would silently reappear. Match the
	// DNS semantics, not the raw bytes.
	host := strings.TrimSuffix(u.Hostname(), ".")
	if strings.EqualFold(host, "localhost") || host == "::1" {
		return true
	}
	// 127.0.0.0/8 — any 127.x.x.x is loopback. net.ParseIP also accepts
	// the ::1 literal, so the named check above is the fast path for the
	// string forms; this handles the numeric forms.
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PutPolicy renders in into the wire shape and uploads it to the
// admin API at PUT /admin/v1/policies/<sandboxIP>. Returns nil on
// 200 OK, a *PermanentError on 4xx, or a generic error on transport
// failures / 5xx (the maintenance loop retries those).
//
// When in has no rules, PutPolicy returns nil without making a call —
// CubeEgress would reject an empty rules array and there's nothing
// useful to install. The caller should treat the absence of rules as
// "no L7 policy for this sandbox", not as a failure.
func (c *Client) PutPolicy(ctx context.Context, sandboxIP string, in *PolicyInput) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	if err := validateSandboxIP(sandboxIP); err != nil {
		return err
	}
	body, err := RenderEgressPolicy(sandboxIP, in)
	if err != nil {
		return err
	}
	if body == nil {
		// No rules to push. Symmetric with the dump endpoint, which
		// also skips entries that have no rules — keeps the two paths
		// telling the same story.
		return nil
	}
	return c.do(ctx, http.MethodPut, "/admin/v1/policies/"+sandboxIP, body)
}

// DeletePolicy removes the policy for sandboxIP from CubeEgress.
// CubeEgress's DELETE is idempotent (lua/policy.lua), so a 200 with a
// nonexistent IP is normal — happens whenever a sandbox without rules
// is released.
func (c *Client) DeletePolicy(ctx context.Context, sandboxIP string) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	if err := validateSandboxIP(sandboxIP); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/admin/v1/policies/"+sandboxIP, nil)
}

// VerifyPolicyAbsent confirms that CubeEgress no longer has policy for
// sandboxIP. Cleanup uses it after DELETE so a transient admin failure cannot
// let an old policy survive until the IP is reused.
func (c *Client) VerifyPolicyAbsent(ctx context.Context, sandboxIP string) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	if err := validateSandboxIP(sandboxIP); err != nil {
		return err
	}
	err := c.do(ctx, http.MethodGet, "/admin/v1/policies/"+sandboxIP, nil)
	if IsNotFound(err) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("cubeegress: policy for %s still exists", sandboxIP)
	}
	return err
}

// do performs one bounded HTTP request and classifies responses for retry
// policy: 2xx success, 4xx permanent caller/configuration error, 5xx/transport
// transient error.
func (c *Client) do(ctx context.Context, method, path string, body []byte) error {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.adminURL+path, reader)
	if err != nil {
		return fmt.Errorf("cubeegress: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("cubeegress: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Drain so the HTTP/1.1 connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &PermanentError{Status: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	return fmt.Errorf("cubeegress: %s %s: %d %s",
		method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
}

// validateSandboxIP makes sure we don't accidentally pump a stray
// "../foo" or empty string into the URL path. CubeEgress's admin
// router itself rejects anything that doesn't match its IPv4 regex,
// but we'd rather fail before the round trip — and we keep the
// validation simple (presence + no path-meaningful chars), since the
// caller is always our own code feeding state.SandboxIP.
func validateSandboxIP(s string) error {
	if s == "" {
		return errors.New("cubeegress: sandbox_ip is empty")
	}
	if strings.ContainsAny(s, "/?#") {
		return fmt.Errorf("cubeegress: sandbox_ip contains URL-meaningful characters: %q", s)
	}
	// We use url.PathEscape under the hood for the standard library
	// req construction, but verify the input is clean rather than
	// silently massaging it — a sandbox IP with weird characters is
	// a bug upstream, not something to paper over.
	if escaped := url.PathEscape(s); escaped != s {
		return fmt.Errorf("cubeegress: sandbox_ip not URL-clean: %q", s)
	}
	return nil
}

// IsConnectionRefused reports whether err is a connection-refused error
// (ECONNREFUSED) from the underlying dialer. The release/cleanup path
// uses it to distinguish "CubeEgress sidecar not running" (bare-metal
// deployments) from transient failures (5xx, timeout, context cancel)
// so a dead loopback port does not stall sandbox deletion forever.
// Callers that retry on transient errors (the create/push path) must
// NOT treat refusal as fatal — they keep retrying, since a sidecar
// restart in the K8s chart momentarily refuses the admin port.
//
// Classification is scoped to the transport error, not the composed
// message: do() builds status errors whose text includes the admin
// response body, and a live sidecar returning a 502 whose body happens
// to contain "connection refused" (e.g. an upstream proxy log line)
// must NOT be downgraded. We unwrap to the inner *url.Error.Err and
// check errors.Is against syscall.ECONNREFUSED, with a string fallback
// only on that inner transport error (covers Windows where the unwrap
// chain sometimes stops at *net.OpError without reaching errno).
func IsConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	// Fast path: the full chain unwraps to ECONNREFUSED on Linux.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// Scope the string fallback to inner transport errors only.
	// net/http wraps dial failures in *url.Error; net dial wraps in
	// *net.OpError. In both cases the meaningful phrasing lives on the
	// inner Err, never on the composed message that includes response
	// bodies (a 502 body containing "connection refused" must NOT
	// match). On Windows the unwrap chain sometimes stops at
	// *net.OpError without reaching errno, so the string fallback is
	// needed there.
	var inner error
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		inner = urlErr.Err
	} else {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Err != nil {
			inner = opErr.Err
		} else {
			return false
		}
	}
	if errors.Is(inner, syscall.ECONNREFUSED) {
		return true
	}
	msg := inner.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused it")
}
