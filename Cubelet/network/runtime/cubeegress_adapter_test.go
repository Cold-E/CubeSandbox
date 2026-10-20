package runtime

import (
	"context"
	"errors"
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

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if adapter.deleteCalls != 1 || adapter.verifyCalls != 1 {
		t.Fatalf("deleteCalls=%d verifyCalls=%d, want 1/1", adapter.deleteCalls, adapter.verifyCalls)
	}
}

// TestDeleteEgressForStateDowngradesConnectionRefused covers the
// bare-metal / non-K8s case: the CubeEgress sidecar is not running, so
// DeletePolicy hits ECONNREFUSED. The release/cleanup path must
// downgrade that to nil so sandbox/template deletion is not stalled
// forever by a dead loopback port (the original "130593 cleanup context
// deadline exceeded" symptom).
func TestDeleteEgressForStateDowngradesConnectionRefused(t *testing.T) {
	refused := errors.New("cubeegress: DELETE /admin/v1/policies/10.0.0.2: dial tcp 127.0.0.1:9091: connect: connection refused")
	adapter := &fakeCubeEgressAdapter{configured: true, deleteErr: refused}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2"); err != nil {
		t.Fatalf("deleteEgressForState err = %v, want nil (connection refused must be downgraded for cleanup)", err)
	}
}

// TestDeleteEgressForStateDowngradesVerifyConnectionRefused covers the
// same bare-metal concession on the VerifyPolicyAbsent step.
func TestDeleteEgressForStateDowngradesVerifyConnectionRefused(t *testing.T) {
	refused := errors.New("cubeegress: GET /admin/v1/policies/10.0.0.2: dial tcp 127.0.0.1:9091: connect: connection refused")
	adapter := &fakeCubeEgressAdapter{configured: true, verifyErr: refused}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	if err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2"); err != nil {
		t.Fatalf("deleteEgressForState err = %v, want nil (verify connection refused must be downgraded)", err)
	}
}

// TestDeleteEgressForStateStillErrorsOnTransient confirms a non-refused
// transient error (5xx, timeout) is NOT downgraded — the TAP stays in
// Cleaning and the maintenance loop retries, which is the existing
// safety guarantee against IP reuse while CubeEgress still holds policy.
func TestDeleteEgressForStateStillErrorsOnTransient(t *testing.T) {
	transient := errors.New("cubeegress: DELETE /admin/v1/policies/10.0.0.2: 502 Bad Gateway")
	adapter := &fakeCubeEgressAdapter{configured: true, deleteErr: transient}
	controller := &NetworkController{cubeEgressAdapter: adapter}

	err := controller.deleteEgressForState(context.Background(), "sandbox1", "10.0.0.2")
	if err == nil {
		t.Fatalf("deleteEgressForState err = nil on transient 5xx, want error (must NOT downgrade non-refused failures)")
	}
}
