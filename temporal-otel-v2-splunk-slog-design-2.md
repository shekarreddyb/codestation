# Temporal + OpenTelemetry v2 + Splunk + slog Logging Design

## Goal

Use a single logging and tracing setup across:

- REST API entrypoints
- Temporal client
- Temporal worker
- Temporal workflows
- Temporal activities
- HTTP client packages
- OpenTelemetry
- Splunk

The desired logging behavior is:

```text
Workflow code     -> workflow.GetLogger(ctx)
Activity code     -> activity.GetLogger(ctx)
HTTP/client code  -> standard logging / slog
Temporal SDK      -> same injected slog logger
All output        -> same OpenTelemetry / Splunk pipeline
```

Every operation should carry these correlation fields:

```text
hostname
correlation_id   <- X-Correlation-ID request header
orid             <- generated UUID
trace_id         <- OpenTelemetry
span_id          <- OpenTelemetry
```

---

# 1. High-Level Architecture

```text
REST Request
|
|-- X-Correlation-ID
|-- hostname from API input
|-- generate ORID
|
v
context.Context
|
|-- OperationContext
|    |-- hostname
|    |-- correlation_id
|    `-- orid
|
`-- OpenTelemetry
     |-- trace/span
     `-- baggage
          |
          v
Temporal ExecuteWorkflow(ctx)
          |
          |-- OTel v2 plugin
          |      `-- trace / baggage propagation
          |
          `-- Temporal ContextPropagator
                 `-- OperationContext propagation
                          |
                     +----+----+
                     |         |
                     v         v
                 Workflow   Activity
```

The core idea is:

- `context.Context` carries operation-specific state.
- `workflow.Context` carries the same state inside workflows.
- Temporal's OTel v2 plugin propagates trace information.
- A custom Temporal `ContextPropagator` propagates business correlation fields.
- A worker interceptor enriches `workflow.GetLogger()` and `activity.GetLogger()`.
- `slog.SetDefault()` provides one global application logging backend.
- The same `slog.Logger` is injected into the Temporal client.

---

# 2. Important Temporal OTel v2 Requirement

The Temporal `opentelemetry-v2` plugin requires a replay-safe tracer provider.

Conceptually:

```go
temporalotel.NewReplaySafeTracerProvider(...)
```

Temporal needs this because workflows replay, and span creation during workflow replay must remain deterministic/replay-safe.

If Splunk's:

```go
distro.Run()
```

also installs its own global tracer provider, do not independently let both Splunk and Temporal own the global tracer provider.

A clean arrangement is:

```text
Splunk distro
    |-- logs
    |-- metrics
    `-- traces disabled

Temporal ReplaySafeTracerProvider
    `-- traces -> same OTLP / Splunk Collector
```

For example:

```bash
OTEL_SERVICE_NAME=my-temporal-worker

OTEL_EXPORTER_OTLP_ENDPOINT=http://splunk-otel-collector:4317

OTEL_LOGS_EXPORTER=otlp
OTEL_METRICS_EXPORTER=otlp

OTEL_TRACES_EXPORTER=none
```

Then explicitly create the Temporal replay-safe trace provider using the OTLP exporter.

---

# 3. Operation Context

Create one structure containing the fields that should follow the operation.

```go
type OperationContext struct {
	Hostname      string `json:"hostname"`
	CorrelationID string `json:"correlation_id"`
	ORID          string `json:"orid"`
}
```

At the API boundary:

```go
op := OperationContext{
	Hostname:      request.Hostname,
	CorrelationID: r.Header.Get("X-Correlation-ID"),
	ORID:          uuid.NewString(),
}
```

If the incoming correlation ID is missing, generate one if desired.

Example:

```go
correlationID := r.Header.Get("X-Correlation-ID")
if correlationID == "" {
	correlationID = uuid.NewString()
}
```

Then:

```go
op := OperationContext{
	Hostname:      request.Hostname,
	CorrelationID: correlationID,
	ORID:          uuid.NewString(),
}
```

---

# 4. Store OperationContext in context.Context

Use a private context key.

```go
type operationContextKey struct{}
```

Helpers:

```go
func WithOperationContext(
	ctx context.Context,
	op OperationContext,
) context.Context {
	return context.WithValue(ctx, operationContextKey{}, op)
}

func OperationContextFromContext(
	ctx context.Context,
) (OperationContext, bool) {
	op, ok := ctx.Value(operationContextKey{}).(OperationContext)
	return op, ok
}
```

For workflow context:

```go
func WithWorkflowOperationContext(
	ctx workflow.Context,
	op OperationContext,
) workflow.Context {
	return workflow.WithValue(ctx, operationContextKey{}, op)
}

func OperationContextFromWorkflow(
	ctx workflow.Context,
) (OperationContext, bool) {
	op, ok := ctx.Value(operationContextKey{}).(OperationContext)
	return op, ok
}
```

---

# 5. Add Correlation Fields to OpenTelemetry

At the API boundary, add the fields to the active span.

```go
span := trace.SpanFromContext(ctx)

span.SetAttributes(
	attribute.String("hostname", op.Hostname),
	attribute.String("correlation_id", op.CorrelationID),
	attribute.String("orid", op.ORID),
)
```

Recommended distinction:

```text
TraceID
    generated and managed by OpenTelemetry

CorrelationID
    business/request correlation identifier

ORID
    application-specific generated operation identifier
```

Do not try to force `X-Correlation-ID` into the actual OpenTelemetry TraceID.

Instead, keep it as:

- span attribute
- baggage value
- log field

This gives you both technical trace correlation and business correlation.

---

# 6. Add Correlation Fields to OTel Baggage

At minimum, propagate:

```text
correlation_id
orid
```

You may also propagate `hostname` if downstream services need it.

Example:

```go
member1, _ := baggage.NewMember(
	"correlation_id",
	op.CorrelationID,
)

member2, _ := baggage.NewMember(
	"orid",
	op.ORID,
)

bag := baggage.FromContext(ctx)

bag, _ = bag.SetMember(member1)
bag, _ = bag.SetMember(member2)

ctx = baggage.ContextWithBaggage(ctx, bag)
```

Temporal OTel v2 can propagate W3C trace context and baggage.

---

# 7. Configure slog Once at Startup

Create one slog logger backed by OpenTelemetry.

Example:

```go
otelHandler := otelslog.NewHandler("my-service")

appLogger := slog.New(otelHandler)

slog.SetDefault(appLogger)
```

Now this becomes the application-wide default logger.

```go
slog.Info("application started")
```

You can also bridge legacy standard-library logging:

```go
log.Printf("something happened")
```

after `slog.SetDefault(...)`.

However, see the important per-request context limitation later in this document.

---

# 8. Inject the Same slog Logger Into Temporal

Temporal provides a structured logger adapter for `slog`.

```go
temporalLogger := temporallog.NewStructuredLogger(
	slog.Default(),
)
```

Then configure the Temporal client:

```go
temporalClient, err := client.Dial(client.Options{
	HostPort:  temporalAddress,
	Namespace: temporalNamespace,

	Logger: temporalLogger,

	Plugins: []client.Plugin{
		otelPlugin,
	},

	ContextPropagators: []workflow.ContextPropagator{
		operationContextPropagator,
	},
})
```

This means Temporal SDK logs ultimately go through the same slog pipeline.

---

# 9. Temporal OTel v2 Plugin

The new OTel v2 plugin should be configured on the Temporal client.

Conceptually:

```go
otelPlugin, err := temporalotel.NewPlugin(
	temporalotel.PluginOptions{
		TracerOptions: tracing.TracerOptions{
			AddTemporalSpans: true,
		},

		TextMapPropagator: otel.GetTextMapPropagator(),
	},
)
```

Then:

```go
Plugins: []client.Plugin{
	otelPlugin,
},
```

Workers created from that client receive the plugin configuration.

---

# 10. Custom Temporal ContextPropagator

OpenTelemetry handles trace/baggage propagation.

Your custom Temporal `ContextPropagator` handles:

```text
hostname
correlation_id
orid
```

A single structure makes propagation easier.

```go
type OperationContext struct {
	Hostname      string `json:"hostname"`
	CorrelationID string `json:"correlation_id"`
	ORID          string `json:"orid"`
}
```

Example propagator:

```go
type OperationContextPropagator struct {
	converter converter.DataConverter
}

const operationContextHeader = "x-operation-context"

func NewOperationContextPropagator() *OperationContextPropagator {
	return &OperationContextPropagator{
		converter: converter.GetDefaultDataConverter(),
	}
}
```

Normal context -> Temporal header:

```go
func (p *OperationContextPropagator) Inject(
	ctx context.Context,
	writer workflow.HeaderWriter,
) error {
	op, ok := OperationContextFromContext(ctx)
	if !ok {
		return nil
	}

	payload, err := p.converter.ToPayload(op)
	if err != nil {
		return err
	}

	writer.Set(operationContextHeader, payload)

	return nil
}
```

Temporal header -> normal context:

```go
func (p *OperationContextPropagator) Extract(
	ctx context.Context,
	reader workflow.HeaderReader,
) (context.Context, error) {
	payload, ok := reader.Get(operationContextHeader)
	if !ok {
		return ctx, nil
	}

	var op OperationContext

	if err := p.converter.FromPayload(
		payload,
		&op,
	); err != nil {
		return ctx, err
	}

	return WithOperationContext(ctx, op), nil
}
```

Workflow context -> Temporal header:

```go
func (p *OperationContextPropagator) InjectFromWorkflow(
	ctx workflow.Context,
	writer workflow.HeaderWriter,
) error {
	op, ok := OperationContextFromWorkflow(ctx)
	if !ok {
		return nil
	}

	payload, err := p.converter.ToPayload(op)
	if err != nil {
		return err
	}

	writer.Set(operationContextHeader, payload)

	return nil
}
```

Temporal header -> workflow context:

```go
func (p *OperationContextPropagator) ExtractToWorkflow(
	ctx workflow.Context,
	reader workflow.HeaderReader,
) (workflow.Context, error) {
	payload, ok := reader.Get(operationContextHeader)
	if !ok {
		return ctx, nil
	}

	var op OperationContext

	if err := p.converter.FromPayload(
		payload,
		&op,
	); err != nil {
		return ctx, err
	}

	return WithWorkflowOperationContext(ctx, op), nil
}
```

The flow becomes:

```text
REST context
    |
    `-- OperationContext
          |
          v
ExecuteWorkflow()
          |
        Inject()
          |
          v
Workflow context
          |
          v
ExecuteActivity()
          |
   InjectFromWorkflow()
          |
          v
Activity context.Context
```

---

# 11. Automatically Enrich workflow.GetLogger()

Inside workflows, use:

```go
logger := workflow.GetLogger(ctx)
```

Do not switch workflow code to direct `slog.InfoContext`.

Workflow logging must remain replay-aware.

The cleanest approach is a Temporal worker interceptor that decorates the logger returned from `workflow.GetLogger(ctx)`.

Conceptually:

```go
type workflowLogOutbound struct {
	interceptor.WorkflowOutboundInterceptorBase
}

func (i *workflowLogOutbound) GetLogger(
	ctx workflow.Context,
) temporallog.Logger {

	logger := i.Next.GetLogger(ctx)

	op, ok := OperationContextFromWorkflow(ctx)
	if !ok {
		return logger
	}

	return temporallog.With(
		logger,
		"hostname", op.Hostname,
		"correlation_id", op.CorrelationID,
		"orid", op.ORID,
	)
}
```

Now workflow code stays simple:

```go
func MyWorkflow(
	ctx workflow.Context,
	input WorkflowInput,
) error {

	logger := workflow.GetLogger(ctx)

	logger.Info("workflow started")

	logger.Info("starting inventory operation")

	return nil
}
```

The log automatically contains fields such as:

```text
message="workflow started"

hostname=server123
correlation_id=ABC123
orid=3a2919dc-...

WorkflowID=...
RunID=...
WorkflowType=...

TraceID=...
SpanID=...
```

---

# 12. Automatically Enrich activity.GetLogger()

Activities should use:

```go
logger := activity.GetLogger(ctx)
```

Use the same enrichment pattern in the activity outbound interceptor.

```go
type activityLogOutbound struct {
	interceptor.ActivityOutboundInterceptorBase
}

func (i *activityLogOutbound) GetLogger(
	ctx context.Context,
) temporallog.Logger {

	logger := i.Next.GetLogger(ctx)

	op, ok := OperationContextFromContext(ctx)
	if !ok {
		return logger
	}

	return temporallog.With(
		logger,
		"hostname", op.Hostname,
		"correlation_id", op.CorrelationID,
		"orid", op.ORID,
	)
}
```

Activity code remains:

```go
func RunAnsible(
	ctx context.Context,
	input AnsibleInput,
) error {

	logger := activity.GetLogger(ctx)

	logger.Info(
		"launching ansible job",
		"template", input.TemplateID,
	)

	return nil
}
```

The log can contain:

```text
hostname
correlation_id
orid

TraceID
SpanID

WorkflowID
RunID

ActivityID
ActivityType
Attempt
```

without manually adding the correlation fields every time.

---

# 13. Worker Interceptor Skeleton

One worker interceptor can handle both workflow and activity logging.

```go
type LoggingInterceptor struct {
	interceptor.WorkerInterceptorBase
}
```

Workflow interception:

```go
func (i *LoggingInterceptor) InterceptWorkflow(
	ctx workflow.Context,
	next interceptor.WorkflowInboundInterceptor,
) interceptor.WorkflowInboundInterceptor {

	return &workflowLogInbound{
		WorkflowInboundInterceptorBase:
			interceptor.WorkflowInboundInterceptorBase{
				Next: next,
			},
	}
}
```

Activity interception:

```go
func (i *LoggingInterceptor) InterceptActivity(
	ctx context.Context,
	next interceptor.ActivityInboundInterceptor,
) interceptor.ActivityInboundInterceptor {

	return &activityLogInbound{
		ActivityInboundInterceptorBase:
			interceptor.ActivityInboundInterceptorBase{
				Next: next,
			},
	}
}
```

Workflow inbound:

```go
type workflowLogInbound struct {
	interceptor.WorkflowInboundInterceptorBase
}

func (i *workflowLogInbound) Init(
	outbound interceptor.WorkflowOutboundInterceptor,
) error {

	wrapped := &workflowLogOutbound{
		WorkflowOutboundInterceptorBase:
			interceptor.WorkflowOutboundInterceptorBase{
				Next: outbound,
			},
	}

	return i.Next.Init(wrapped)
}
```

Activity inbound:

```go
type activityLogInbound struct {
	interceptor.ActivityInboundInterceptorBase
}

func (i *activityLogInbound) Init(
	outbound interceptor.ActivityOutboundInterceptor,
) error {

	wrapped := &activityLogOutbound{
		ActivityOutboundInterceptorBase:
			interceptor.ActivityOutboundInterceptorBase{
				Next: outbound,
			},
	}

	return i.Next.Init(wrapped)
}
```

The outbound interceptors then override `GetLogger()`.

---

# 14. Interceptor Composition

The Temporal OTel tracing interceptor also decorates workflow/activity loggers with tracing information.

The desired logical chain is:

```text
workflow.GetLogger(ctx)
        |
        v
Temporal tracing interceptor
        |
        + TraceID
        + SpanID
        |
        v
Your logging interceptor
        |
        + hostname
        + correlation_id
        + orid
        |
        v
Temporal slog adapter
        |
        v
slog
        |
        v
OpenTelemetry
        |
        v
Splunk
```

The same applies to:

```go
activity.GetLogger(ctx)
```

This provides:

```text
Temporal metadata
+
OTel trace metadata
+
application correlation metadata
```

---

# 15. REST Endpoint Example

A simplified REST handler:

```go
func StartWorkflow(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	var request StartRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	correlationID := r.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = uuid.NewString()
	}

	op := OperationContext{
		Hostname:      request.Hostname,
		CorrelationID: correlationID,
		ORID:          uuid.NewString(),
	}

	ctx = WithOperationContext(ctx, op)

	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String("hostname", op.Hostname),
		attribute.String("correlation_id", op.CorrelationID),
		attribute.String("orid", op.ORID),
	)

	run, err := temporalClient.ExecuteWorkflow(
		ctx,
		client.StartWorkflowOptions{
			ID:        "server-" + request.Hostname,
			TaskQueue: "server-worker",
		},
		MyWorkflow,
		request,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = run
}
```

---

# 16. HTTP Client Packages

There is an important distinction here.

After:

```go
slog.SetDefault(appLogger)
```

legacy code can continue doing:

```go
log.Printf("calling inventory API")
```

and its output can flow through the same global logging backend.

However:

```go
log.Printf(...)
```

does not accept a `context.Context`.

Therefore it cannot automatically know which concurrent operation owns:

```text
hostname
correlation_id
orid
trace_id
span_id
```

Example:

```text
goroutine 1
    hostname = server-A
    correlation_id = C1

goroutine 2
    hostname = server-B
    correlation_id = C2
```

Both execute:

```go
log.Printf("calling API")
```

The global logger cannot know which request owns that log line.

Do not dynamically do this per request:

```go
slog.SetDefault(
	slog.Default().With(
		"hostname", hostname,
	),
)
```

That would create incorrect data under concurrency.

---

# 17. Preferred HTTP Client Logging

If the HTTP client package is your code, pass `context.Context`.

For example:

```go
func (c *TowerClient) Launch(
	ctx context.Context,
	server string,
) error {

	slog.InfoContext(
		ctx,
		"calling ansible tower",
		"server",
		server,
	)

	// ...
	return nil
}
```

You are not injecting a logger.

You are still using the global:

```go
slog.Default()
```

The context gives the handler access to:

```text
hostname
correlation_id
orid
trace_id
span_id
```

if you configure a context-enriching slog handler.

---

# 18. Context-Enriching slog Handler

You can wrap the OTel slog handler.

```go
type ContextHandler struct {
	next slog.Handler
}
```

Constructor:

```go
func NewContextHandler(next slog.Handler) slog.Handler {
	return &ContextHandler{
		next: next,
	}
}
```

Enabled:

```go
func (h *ContextHandler) Enabled(
	ctx context.Context,
	level slog.Level,
) bool {
	return h.next.Enabled(ctx, level)
}
```

Handle:

```go
func (h *ContextHandler) Handle(
	ctx context.Context,
	record slog.Record,
) error {

	record = record.Clone()

	if op, ok := OperationContextFromContext(ctx); ok {
		record.AddAttrs(
			slog.String("hostname", op.Hostname),
			slog.String("correlation_id", op.CorrelationID),
			slog.String("orid", op.ORID),
		)
	}

	spanContext := trace.SpanContextFromContext(ctx)

	if spanContext.IsValid() {
		record.AddAttrs(
			slog.String(
				"trace_id",
				spanContext.TraceID().String(),
			),
			slog.String(
				"span_id",
				spanContext.SpanID().String(),
			),
		)
	}

	return h.next.Handle(ctx, record)
}
```

WithAttrs:

```go
func (h *ContextHandler) WithAttrs(
	attrs []slog.Attr,
) slog.Handler {
	return &ContextHandler{
		next: h.next.WithAttrs(attrs),
	}
}
```

WithGroup:

```go
func (h *ContextHandler) WithGroup(
	name string,
) slog.Handler {
	return &ContextHandler{
		next: h.next.WithGroup(name),
	}
}
```

Startup:

```go
otelHandler := otelslog.NewHandler("my-service")

contextHandler := NewContextHandler(otelHandler)

appLogger := slog.New(contextHandler)

slog.SetDefault(appLogger)
```

Now application code can use:

```go
slog.InfoContext(
	ctx,
	"calling inventory API",
)
```

and automatically get operation and trace fields.

---

# 19. Instrument Outbound HTTP Calls

Use `otelhttp.NewTransport`.

```go
httpClient := &http.Client{
	Transport: otelhttp.NewTransport(
		http.DefaultTransport,
	),
}
```

Then create requests using the same context:

```go
req, err := http.NewRequestWithContext(
	ctx,
	http.MethodPost,
	url,
	body,
)
```

The current OTel trace context is propagated automatically.

If downstream systems specifically expect `X-Correlation-ID`, set it explicitly:

```go
if op, ok := OperationContextFromContext(ctx); ok {
	req.Header.Set(
		"X-Correlation-ID",
		op.CorrelationID,
	)

	req.Header.Set(
		"X-ORID",
		op.ORID,
	)
}
```

This gives:

```text
Temporal Activity
      |
      | context.Context
      |-- trace
      |-- correlation_id
      |-- orid
      `-- hostname
      |
      v
HTTP Client
      |
      |-- traceparent
      |-- baggage
      |-- X-Correlation-ID
      `-- X-ORID
      |
      v
Downstream API
```

---

# 20. Logging Convention

Use the following project convention.

## Workflow code

Always:

```go
logger := workflow.GetLogger(ctx)

logger.Info("workflow started")
```

Why:

- replay-aware
- Temporal metadata
- OTel TraceID / SpanID
- your correlation fields via interceptor

---

## Activity code

Always:

```go
logger := activity.GetLogger(ctx)

logger.Info("activity started")
```

Why:

- Temporal activity metadata
- OTel TraceID / SpanID
- your correlation fields via interceptor

---

## HTTP / API / database / application packages

Preferred:

```go
slog.InfoContext(
	ctx,
	"calling external API",
)
```

Why:

- same global slog logger
- no logger injection
- context-aware enrichment
- OTel correlation

---

## Startup / process-wide logging

Use:

```go
slog.Info("worker starting")
```

These logs are not associated with a particular workflow/request, so request-specific fields are not expected.

---

## Legacy / third-party standard log package

This is acceptable:

```go
log.Printf("library initialized")
```

It can still flow through the default slog backend after `slog.SetDefault()`.

However, it will not reliably contain per-request fields because it has no `context.Context`.

---

# 21. Final Logging Flow

```text
                     +---------------------------+
                     |          slog             |
                     |      slog.Default()       |
                     +-------------+-------------+
                                   |
                +------------------+------------------+
                |                  |                  |
                v                  v                  v
          Temporal SDK       App packages        legacy log
                |                  |                  |
     workflow.GetLogger      slog.InfoContext      log.Printf
     activity.GetLogger            |                  |
                |                  |                  |
                +------------------+------------------+
                                   |
                                   v
                           ContextHandler
                                   |
                   +---------------+---------------+
                   |                               |
                   v                               v
            OperationContext                 SpanContext
            - hostname                       - trace_id
            - correlation_id                 - span_id
            - orid
                   \                               /
                    +-------------+---------------+
                                  |
                                  v
                           otelslog.Handler
                                  |
                                  v
                          OTel LoggerProvider
                                  |
                                  v
                          Splunk Collector
                                  |
                                  v
                               Splunk
```

---

# 22. Recommended Field Names

Choose a single naming convention and keep it stable in Splunk.

Recommended:

```text
hostname
correlation_id
orid

trace_id
span_id

workflow_id
workflow_run_id
workflow_type

activity_id
activity_type
activity_attempt
```

If your organization already uses OTel semantic conventions or Splunk-specific naming, align with those instead.

---

# 23. Final Rules

## Rule 1

One global `slog.Logger`:

```go
slog.SetDefault(appLogger)
```

---

## Rule 2

Inject the same logger into Temporal:

```go
Logger: temporallog.NewStructuredLogger(
	slog.Default(),
)
```

---

## Rule 3

Inside workflows use:

```go
workflow.GetLogger(ctx)
```

not direct slog calls.

---

## Rule 4

Inside activities use:

```go
activity.GetLogger(ctx)
```

---

## Rule 5

Use a Temporal worker interceptor so both workflow/activity loggers automatically contain:

```text
hostname
correlation_id
orid
```

---

## Rule 6

Let Temporal OTel v2 supply trace correlation:

```text
TraceID
SpanID
```

---

## Rule 7

Use a custom Temporal `ContextPropagator` for:

```text
hostname
correlation_id
orid
```

---

## Rule 8

Use OTel baggage for cross-service correlation values such as:

```text
correlation_id
orid
```

---

## Rule 9

For your own normal Go packages prefer:

```go
slog.InfoContext(ctx, ...)
```

instead of:

```go
log.Printf(...)
```

when operation-specific enrichment is required.

---

## Rule 10

Do not mutate `slog.Default()` per request.

This is unsafe under concurrency.

---

# 24. Desired End Result

A workflow log:

```text
message="starting provisioning workflow"

hostname=server123
correlation_id=CORR-44281
orid=37cbac07-4d89-4cc3-a96b-5ce7f2518f48

trace_id=74ca35f...
span_id=12ca4...

workflow_id=provision-server123
workflow_run_id=...
workflow_type=ProvisionServer
```

An activity log:

```text
message="launching ansible job"

hostname=server123
correlation_id=CORR-44281
orid=37cbac07-4d89-4cc3-a96b-5ce7f2518f48

trace_id=74ca35f...
span_id=5fac8...

workflow_id=provision-server123
activity_id=7
activity_type=LaunchAnsible
activity_attempt=1
```

An application/HTTP client log:

```text
message="calling ansible tower"

hostname=server123
correlation_id=CORR-44281
orid=37cbac07-4d89-4cc3-a96b-5ce7f2518f48

trace_id=74ca35f...
span_id=92bc1...
```

All of these records can then be searched in Splunk by any of:

```text
hostname=server123
correlation_id=CORR-44281
orid=37cbac07-4d89-4cc3-a96b-5ce7f2518f48
trace_id=74ca35f...
```

This gives one consistent correlation model from the REST endpoint through Temporal workflows and activities and into downstream HTTP calls.
