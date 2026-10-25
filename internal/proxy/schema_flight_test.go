package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// gatedUpstream5 holds every GetSchema until gate closes, then answers with
// fake_thing or, while fail is set, an error.
type gatedUpstream5 struct {
	tfplugin5.UnimplementedProviderServer
	calls atomic.Int32
	gate  chan struct{}
	fail  atomic.Bool
}

func (f *gatedUpstream5) GetSchema(ctx context.Context, _ *tfplugin5.GetProviderSchema_Request) (*tfplugin5.GetProviderSchema_Response, error) {
	f.calls.Add(1)
	select {
	case <-f.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.fail.Load() {
		return nil, status.Error(codes.Unavailable, "upstream down")
	}
	return &tfplugin5.GetProviderSchema_Response{ResourceSchemas: map[string]*tfplugin5.Schema{"fake_thing": {Block: &tfplugin5.Schema_Block{}}}}, nil
}

// schemaOfAll runs n concurrent schemaOf(fake_thing) calls on a cold cache
// and returns their errors once all have finished.
func schemaOfAll(ctx context.Context, p *server5, n int) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, ok, err := p.schemaOf(ctx, "fake_thing", schemasOf[hook.KindResource])
			if err == nil && !ok {
				err = errors.New("fake_thing absent")
			}
			errs[i] = err
		})
	}
	wg.Wait()
	return errs
}

// TestSchemaOfColdCacheSingleFetch: concurrent resources missing the cold
// cache share one upstream GetSchema.
func TestSchemaOfColdCacheSingleFetch(t *testing.T) {
	up := &gatedUpstream5{gate: make(chan struct{})}
	_, p := startProxy(t, up, Backends{})
	time.AfterFunc(100*time.Millisecond, func() { close(up.gate) })
	for i, err := range schemaOfAll(context.Background(), p, 16) {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream GetSchema calls = %d, want 1", n)
	}
}

// TestSchemaOfFailedFetchRetries: a failed fetch reaches its waiters, is not
// cached, and the next caller fetches again. Sharing is asserted by
// TestSchemaOfColdCacheSingleFetch: here a late caller may start its own
// failing flight.
func TestSchemaOfFailedFetchRetries(t *testing.T) {
	up := &gatedUpstream5{gate: make(chan struct{})}
	up.fail.Store(true)
	_, p := startProxy(t, up, Backends{})
	time.AfterFunc(100*time.Millisecond, func() { close(up.gate) })
	for i, err := range schemaOfAll(context.Background(), p, 8) {
		if err == nil {
			t.Fatalf("caller %d: no error from a failed fetch", i)
		}
	}
	if p.cachedSchema() != nil {
		t.Fatal("failed fetch cached")
	}
	up.fail.Store(false)
	before := up.calls.Load()
	if _, ok, err := p.schemaOf(context.Background(), "fake_thing", schemasOf[hook.KindResource]); err != nil || !ok {
		t.Fatalf("retry after failure = %v, %v; want found", ok, err)
	}
	if n := up.calls.Load() - before; n != 1 {
		t.Fatalf("upstream GetSchema calls for the retry = %d, want 1", n)
	}
}

// waitCalls waits up to 5 s for n upstream GetSchema calls.
func waitCalls(t *testing.T, up *gatedUpstream5, n int32) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); up.calls.Load() < n; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("upstream GetSchema calls = %d after 5 s, want %d", up.calls.Load(), n)
		}
	}
}

// TestSchemaOfHungFetchExpires: a shared fetch that never answers ends at
// schemaFetchTimeout, and the next caller starts a fresh fetch.
func TestSchemaOfHungFetchExpires(t *testing.T) {
	defer func(d time.Duration) { schemaFetchTimeout = d }(schemaFetchTimeout)
	schemaFetchTimeout = 50 * time.Millisecond
	up := &gatedUpstream5{gate: make(chan struct{})}
	_, p := startProxy(t, up, Backends{})
	if _, _, err := p.schemaOf(context.Background(), "fake_thing", schemasOf[hook.KindResource]); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("hung fetch err = %v, want DeadlineExceeded", err)
	}
	close(up.gate)
	if _, ok, err := p.schemaOf(context.Background(), "fake_thing", schemasOf[hook.KindResource]); err != nil || !ok {
		t.Fatalf("fetch after the hung one = %v, %v; want found", ok, err)
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream GetSchema calls = %d, want 2", n)
	}
}

// TestSchemaOfWaiterCancel: a waiter whose context ends returns at once with
// that error; the shared fetch still completes for the others.
func TestSchemaOfWaiterCancel(t *testing.T) {
	up := &gatedUpstream5{gate: make(chan struct{})}
	_, p := startProxy(t, up, Backends{})
	first := make(chan error, 1)
	go func() {
		_, _, err := p.schemaOf(context.Background(), "fake_thing", schemasOf[hook.KindResource])
		first <- err
	}()
	waitCalls(t, up, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := p.schemaOf(ctx, "fake_thing", schemasOf[hook.KindResource]); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("canceled waiter err = %v, want DeadlineExceeded", err)
	}
	close(up.gate)
	if err := <-first; err != nil {
		t.Fatalf("first caller: %v", err)
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream GetSchema calls = %d, want 1", n)
	}
}
