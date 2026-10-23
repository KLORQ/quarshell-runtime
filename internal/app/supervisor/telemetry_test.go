package supervisor

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	collectorpb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

type supervisorTraceCollector struct {
	mu      sync.Mutex
	request *collectorpb.ExportTraceServiceRequest
}

func TestSupervisorTelemetryExportsSpanWithW3CParent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &supervisorTraceCollector{}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "opentelemetry.proto.collector.trace.v1.TraceService",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Export", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			request := new(collectorpb.ExportTraceServiceRequest)
			if err := decode(request); err != nil {
				return nil, err
			}
			collector.mu.Lock()
			collector.request = request
			collector.mu.Unlock()
			return &collectorpb.ExportTraceServiceResponse{}, nil
		}}},
	}, collector)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	provider, tracer, parent, err := configureSupervisorTelemetry(t.Context(), "http://"+listener.Addr().String(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "")
	if err != nil {
		t.Fatal(err)
	}
	_, span := tracer.Start(parent, "supervisor.run")
	span.End()
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := provider.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}

	collector.mu.Lock()
	request := collector.request
	collector.mu.Unlock()
	if request == nil || len(request.ResourceSpans) != 1 {
		t.Fatalf("collector received no supervisor spans: %#v", request)
	}
	resourceSpans := request.ResourceSpans[0]
	serviceFound := false
	for _, attr := range resourceSpans.Resource.Attributes {
		serviceFound = serviceFound || attr.Key == "service.name" && attr.Value.GetStringValue() == "quarshell-supervisor"
	}
	wantParent, _ := hex.DecodeString("00f067aa0ba902b7")
	parentFound := false
	for _, scope := range resourceSpans.ScopeSpans {
		for _, exported := range scope.Spans {
			parentFound = parentFound || bytes.Equal(exported.ParentSpanId, wantParent)
		}
	}
	if !serviceFound || !parentFound {
		t.Fatalf("service name=%v parent span=%v", serviceFound, parentFound)
	}
}

func TestSupervisorTelemetryRejectsMalformedEndpoint(t *testing.T) {
	if _, _, _, err := configureSupervisorTelemetry(t.Context(), "://invalid", "", ""); err == nil {
		t.Fatal("malformed OTLP endpoint was accepted")
	}
}
