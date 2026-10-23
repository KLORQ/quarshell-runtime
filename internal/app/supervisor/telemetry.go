package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	supervisorOTLPEndpointEnv          = "OPENSHELL_OTLP_ENDPOINT"
	supervisorTraceParentEnv           = "TRACEPARENT"
	supervisorTraceStateEnv            = "TRACESTATE"
	supervisorTelemetryShutdownTimeout = 5 * time.Second
)

// configureSupervisorTelemetry creates an isolated OTLP provider. It does not
// install global propagators or resource detectors in the guest process.
func configureSupervisorTelemetry(ctx context.Context, endpoint, traceparent, tracestate string) (*sdktrace.TracerProvider, trace.Tracer, context.Context, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, nil, context.Background(), nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, nil, context.Background(), fmt.Errorf("endpoint must be an absolute HTTP(S) URL with a host")
	}
	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(endpoint))
	if err != nil {
		return nil, nil, context.Background(), errors.New("create OTLP exporter")
	}
	res := resource.NewSchemaless(attribute.String("service.name", "quarshell-supervisor"))
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	parent := propagation.TraceContext{}.Extract(context.Background(), propagation.MapCarrier{
		"traceparent": traceparent,
		"tracestate":  tracestate,
	})
	return provider, provider.Tracer("github.com/KLORQ/quarshell-runtime/internal/app/supervisor"), parent, nil
}
