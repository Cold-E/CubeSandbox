package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/tencentcloud/CubeSandbox/Cubelet/network/runtime/cubeegress"
)

type fakeCubeEgressAdapter struct {
	configured  bool
	putErr      error
	putErrs     []error
	deleteErr   error
	verifyErr   error
	putCalls    int
	deleteCalls int
	verifyCalls int
	recorder    *createOrderRecorder
}

func (f *fakeCubeEgressAdapter) Configured() bool {
	return f.configured
}

func (f *fakeCubeEgressAdapter) PutPolicy(_ context.Context, _ string, _ *cubeegress.PolicyInput) error {
	if f.recorder != nil {
		f.recorder.record("cubeegress_put")
	}
	f.putCalls++
	if len(f.putErrs) > 0 {
		err := f.putErrs[0]
		f.putErrs = f.putErrs[1:]
		return err
	}
	return f.putErr
}

func (f *fakeCubeEgressAdapter) DeletePolicy(_ context.Context, _ string) error {
	if f.recorder != nil {
		f.recorder.record("cubeegress_delete")
	}
	f.deleteCalls++
	return f.deleteErr
}

func (f *fakeCubeEgressAdapter) VerifyPolicyAbsent(_ context.Context, _ string) error {
	if f.recorder != nil {
		f.recorder.record("cubeegress_verify")
	}
	f.verifyCalls++
	return f.verifyErr
}

func TestPushEgressForStateRetriesTransientFailures(t *testing.T) {
	oldDelays := egressCreatePushRetryDelays
	egressCreatePushRetryDelays = []time.Duration{0, 0}
	defer func() { egressCreatePushRetryDelays = oldDelays }()

	adapter := &fakeCubeEgressAdapter{configured: true, putErrs: []error{
		errors.New("temporary unavailable"),
		errors.New("connection refused"),
		nil,
	}}
	controller := &NetworkController{cubeEgressAdapter: adapter}
	state := newEgressPolicyTestState()

	if err := controller.pushEgressForState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if adapter.putCalls != 3 {
		t.Fatalf("putCalls = %d, want 3", adapter.putCalls)
	}
}

func TestPushEgressForStateReturnsTransientErrorAfterRetries(t *testing.T) {
	oldDelays := egressCreatePushRetryDelays
	egressCreatePushRetryDelays = []time.Duration{0, 0}
	defer func() { egressCreatePushRetryDelays = oldDelays }()

	adapter := &fakeCubeEgressAdapter{configured: true, putErr: errors.New("temporary unavailable")}
	controller := &NetworkController{cubeEgressAdapter: adapter}
	state := newEgressPolicyTestState()

	if err := controller.pushEgressForState(context.Background(), state); err == nil {
		t.Fatal("expected put error")
	}
	if adapter.putCalls != 3 {
		t.Fatalf("putCalls = %d, want 3", adapter.putCalls)
	}
}

func TestPushEgressForStateDoesNotRetryPermanentError(t *testing.T) {
	adapter := &fakeCubeEgressAdapter{configured: true, putErr: &cubeegress.PermanentError{Status: 400, Body: "bad request"}}
	controller := &NetworkController{cubeEgressAdapter: adapter}
	state := newEgressPolicyTestState()

	if err := controller.pushEgressForState(context.Background(), state); err == nil {
		t.Fatal("expected permanent error")
	}
	if adapter.putCalls != 1 {
		t.Fatalf("putCalls = %d, want 1", adapter.putCalls)
	}
}

func newEgressPolicyTestState() *managedState {
	return &managedState{persistedState: persistedState{
		SandboxID: "sandbox1",
		SandboxIP: "10.0.0.2",
		CubeNetworkConfig: &CubeNetworkConfig{Rules: []*EgressRule{{
			Name:   "rule1",
			Action: &EgressRuleAction{Allow: true},
		}}},
	}}
}

func TestDeleteEgressForStateDeletesAndVerifies(t *testing.T) {
	adapter := &fakeCubeEgressAdapter{configured: true}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2", true); err != nil {
		t.Fatal(err)
	}
	if adapter.deleteCalls != 1 || adapter.verifyCalls != 1 {
		t.Fatalf("deleteCalls=%d verifyCalls=%d, want 1/1", adapter.deleteCalls, adapter.verifyCalls)
	}
}

// refusedEgressError builds the exact error shape the real client returns on a
// connection-refused: a *url.Error wrapping a *net.OpError wrapping ECONNREFUSED.
// IsConnectionRefused only inspects the inner transport error, never the
// composed message, so the fixture must carry the unwrap chain — a plain
// errors.New("... connection refused") would NOT match.
func refusedEgressError(method, path string) error {
	return fmt.Errorf("cubeegress: %s %s: %w", method, path, &url.Error{
		Op:  method,
		URL: "http://127.0.0.1:9091" + path,
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
	})
}

// TestDeleteEgressForStateDowngradesConnectionRefused covers the bare-metal /
// non-K8s case on the release/cleanup path: the CubeEgress sidecar is not
// running, so DeletePolicy hits ECONNREFUSED. The release caller passes
// allowDowngrade=true and the cleanup proceeds with a warning instead of
// stalling sandbox/template deletion forever.
func TestDeleteEgressForStateDowngradesConnectionRefused(t *testing.T) {
	refused := refusedEgressError("DELETE", "/admin/v1/policies/10.0.0.2")
	adapter := &fakeCubeEgressAdapter{configured: true, deleteErr: refused}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2", true); err != nil {
		t.Fatalf("deleteEgressForState err = %v, want nil (connection refused must be downgraded on release path)", err)
	}
}

// TestDeleteEgressForStateDowngradesVerifyConnectionRefused covers the same
// bare-metal concession on the VerifyPolicyAbsent step.
func TestDeleteEgressForStateDowngradesVerifyConnectionRefused(t *testing.T) {
	refused := refusedEgressError("GET", "/admin/v1/policies/10.0.0.2")
	adapter := &fakeCubeEgressAdapter{configured: true, verifyErr: refused}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2", true); err != nil {
		t.Fatalf("deleteEgressForState err = %v, want nil (verify connection refused must be downgraded on release path)", err)
	}
}

// TestDeleteEgressForStateKeepsRefusedStrictOnLiveUpdate guards the live
// policy-update path (syncEgressPolicy removing the last L7 rule from a
// running sandbox): allowDowngrade=false means a refused delete is NOT
// downgraded, so the previous policy/secrets are not leaked in CubeEgress
// while the sandbox is still alive.
func TestDeleteEgressForStateKeepsRefusedStrictOnLiveUpdate(t *testing.T) {
	refused := refusedEgressError("DELETE", "/admin/v1/policies/10.0.0.2")
	adapter := &fakeCubeEgressAdapter{configured: true, deleteErr: refused}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2", false)
	if err == nil {
		t.Fatalf("deleteEgressForState err = nil on refused with allowDowngrade=false, want error (live update must stay strict)")
	}
	if !cubeegress.IsConnectionRefused(err) {
		t.Fatalf("err = %v, want a connection-refused error to surface to the caller", err)
	}
}

// TestDeleteEgressForStateStillErrorsOnTransient confirms a non-refused
// transient error (5xx, timeout) is NOT downgraded even on the release
// path — the TAP stays in Cleaning and the maintenance loop retries,
// preserving the IP-reuse safety guarantee.
func TestDeleteEgressForStateStillErrorsOnTransient(t *testing.T) {
	transient := errors.New("cubeegress: DELETE /admin/v1/policies/10.0.0.2: 502 Bad Gateway")
	adapter := &fakeCubeEgressAdapter{configured: true, deleteErr: transient}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2", true)
	if err == nil {
		t.Fatalf("deleteEgressForState err = nil on transient 5xx, want error (must NOT downgrade non-refused failures)")
	}
}
