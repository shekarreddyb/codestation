# Temporal + slog + OpenTelemetry v2 + Correlation Context Design

## Goal

Build a clean logging and tracing model for a Go service that:

- exposes a REST endpoint
- starts Temporal workflows
- runs Temporal activities
- calls downstream HTTP APIs
- uses `slog` as the application logger
- uses `workflow.GetLogger(ctx)` inside workflows
- uses `activity.GetLogger(ctx)` inside activities
- uses OpenTelemetry v2 with Temporal
- exports traces to Splunk
- carries the same correlation information across the whole execution

The operation-specific values are:

```text
hostname
correlation_id   <- incoming X-Correlation-ID header
orid             <- generated UUID for the operation
```

OpenTelemetry also maintains:

```text
trace_id
span_id
```

The important design principle is:

```text
Logger
    = where logs go

Context
    = which operation/request this is

Temporal ContextPropagator
    = moves custom application metadata across Temporal boundaries

OTel propagation
    = moves trace context and baggage

Logging interceptor / slog handler
    = enriches logs using context values
```

---

# 1. Do Not Store the Logger in context.Context

A pattern you may see is:

```go
ctx = context.WithValue(ctx, loggerKey{}, logger)
```

and later:

```go
logger := LoggerFromContext(ctx)
logger.Info("something happened")
```

This works technically, but it is usually not the cleanest design.

The logger becomes a hidden dependency of every function that receives a context.

The cleaner pattern is:

```text
one shared base logger
+
context contains request/operation metadata
```

So configure the shared logger once:

```go
slog.SetDefault(logger)
```

Then normal Go code can use:

```go
slog.InfoContext(ctx, "calling inventory")
```

The logger itself is shared. The context only contains values such as:

```text
hostname
correlation_id
orid
trace/span information
```

---

# 2. What Should Be Stored in Context

Request-scoped or operation-scoped values are good candidates.

```go
type OperationContext struct {
    Hostname      string
    CorrelationID string
    ORID          string
}
```

Conceptually:

```text
context.Context
│
├── OperationContext
│   ├── hostname
│   ├── correlation_id
│   └── orid
│
├── OpenTelemetry SpanContext
│   ├── TraceID
│   └── SpanID
│
└── OpenTelemetry Baggage
    ├── correlation_id
    └── orid
```

The logger itself does not need to be stored there.

---

# 3. Logger Setup

Create the logger normally and configure the minimum log level.

```go
func configureLogging() {
    var level slog.LevelVar
    level.Set(slog.LevelInfo)

    handler := slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            Level:     &level,
            AddSource: true,
        },
    )

    logger := slog.New(handler)
    slog.SetDefault(logger)
}
```

This logger can stay independent from OpenTelemetry tracing.

For example:

```text
slog
    -> stdout / structured JSON
    -> log collector
    -> Splunk
```

while tracing uses:

```text
OTel SDK
    -> OTLP
    -> Splunk Collector
    -> Splunk
```

---

# 4. Give Temporal the Same slog Logger

Temporal expects its own logging interface, so use the slog adapter:

```go
temporalLogger := temporallog.NewStructuredLogger(
    slog.Default(),
)
```

Then configure the client:

```go
temporalClient, err := client.Dial(
    client.Options{
        HostPort:  temporalAddress,
        Namespace: temporalNamespace,

        Logger: temporalLogger,

        Plugins: []client.Plugin{
            otelPlugin,
        },

        ContextPropagators: []workflow.ContextPropagator{
            operationContextPropagator,
        },
    },
)
```

The logging flow becomes:

```text
workflow.GetLogger(ctx)
activity.GetLogger(ctx)
Temporal SDK internal logs
          │
          ▼
Temporal log.Logger
          │
          ▼
slog.Default()
          │
          ▼
your slog.Handler
```

---

# 5. Recommended Logging Convention

## Workflow code

Use:

```go
logger := workflow.GetLogger(ctx)
logger.Info("workflow started")
```

Do not use ordinary slog directly in workflow code. Temporal workflow logging is replay-aware.

## Activity code

Use:

```go
logger := activity.GetLogger(ctx)
logger.Info("activity started")
```

## Normal Go / HTTP client code

Use:

```go
slog.InfoContext(ctx, "calling external API")
```

The method is `slog.InfoContext(...)`.

## Startup / process-wide logs

Use:

```go
slog.Info("worker starting")
```

---

# 6. Create Operation Metadata at the REST Boundary

The REST endpoint is the correct place to create the operation-specific values.

```go
func StartWorkflow(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

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

    // Add baggage/span attributes, then start Temporal.
}
```

---

# 7. Clean Context Helper

Keep context access in one package instead of scattering `context.WithValue` throughout the codebase.

Suggested package layout:

```text
internal/
    observability/
        context.go
        logging.go
        propagation.go
        tracing.go
```

`context.go`:

```go
package observability

import (
    "context"

    "go.temporal.io/sdk/workflow"
)

type OperationContext struct {
    Hostname      string
    CorrelationID string
    ORID          string
}

type operationContextKey struct{}
```

Normal Go helpers:

```go
func WithOperationContext(
    ctx context.Context,
    op OperationContext,
) context.Context {
    return context.WithValue(
        ctx,
        operationContextKey{},
        op,
    )
}

func OperationContextFromContext(
    ctx context.Context,
) (OperationContext, bool) {
    op, ok := ctx.Value(
        operationContextKey{},
    ).(OperationContext)

    return op, ok
}
```

Workflow helpers:

```go
func WithWorkflowOperationContext(
    ctx workflow.Context,
    op OperationContext,
) workflow.Context {
    return workflow.WithValue(
        ctx,
        operationContextKey{},
        op,
    )
}

func OperationContextFromWorkflow(
    ctx workflow.Context,
) (OperationContext, bool) {
    op, ok := ctx.Value(
        operationContextKey{},
    ).(OperationContext)

    return op, ok
}
```

---

# 8. Start the Workflow Using the REST Context

After creating the operation metadata:

```go
ctx = WithOperationContext(ctx, op)
```

start Temporal with that context:

```go
run, err := temporalClient.ExecuteWorkflow(
    ctx,
    client.StartWorkflowOptions{
        ID:        workflowID,
        TaskQueue: taskQueue,
    },
    MyWorkflow,
    request,
)
```

Temporal does not automatically serialize arbitrary values stored in `context.Context`. That is why a custom `ContextPropagator` is required.

---

# 9. Temporal ContextPropagator

The propagator handles four directions:

```text
normal Go context -> Temporal headers
Temporal headers  -> normal Go context
workflow.Context  -> Temporal headers
Temporal headers  -> workflow.Context
```

The key methods are:

```go
Inject(...)
Extract(...)
InjectFromWorkflow(...)
ExtractToWorkflow(...)
```

---

# 10. Propagator Structure

```go
type OperationContextPropagator struct {
    dataConverter converter.DataConverter
}

const operationContextHeader = "operation-context"

func NewOperationContextPropagator() *OperationContextPropagator {
    return &OperationContextPropagator{
        dataConverter: converter.GetDefaultDataConverter(),
    }
}
```

---

# 11. REST -> Workflow: Inject

When `ExecuteWorkflow(ctx, ...)` is called, read the operation data from the normal Go context and write it into Temporal headers.

```go
func (p *OperationContextPropagator) Inject(
    ctx context.Context,
    writer workflow.HeaderWriter,
) error {
    op, ok := OperationContextFromContext(ctx)
    if !ok {
        return nil
    }

    payload, err := p.dataConverter.ToPayload(op)
    if err != nil {
        return err
    }

    writer.Set(operationContextHeader, payload)
    return nil
}
```

Flow:

```text
context.Context
      │
      │ OperationContext
      ▼
Inject()
      │
      ▼
Temporal Header
```

---

# 12. REST -> Workflow: ExtractToWorkflow

The worker reconstructs the metadata into `workflow.Context`:

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

    if err := p.dataConverter.FromPayload(payload, &op); err != nil {
        return ctx, err
    }

    return WithWorkflowOperationContext(ctx, op), nil
}
```

Now the workflow context has:

```text
workflow.Context
│
├── hostname
├── correlation_id
└── orid
```

---

# 13. Access Metadata Inside a Workflow

```go
func MyWorkflow(
    ctx workflow.Context,
    input WorkflowInput,
) error {
    op, ok := OperationContextFromWorkflow(ctx)

    if ok {
        _ = op.Hostname
        _ = op.CorrelationID
        _ = op.ORID
    }

    logger := workflow.GetLogger(ctx)
    logger.Info("workflow started")

    return nil
}
```

Do not pass `workflow.Context` as activity data:

```go
// Wrong
workflow.ExecuteActivity(ctx, MyActivity, ctx)
```

Use the context normally:

```go
workflow.ExecuteActivity(ctx, MyActivity, input)
```

---

# 14. Workflow -> Activity Propagation

When the workflow executes an activity, the same propagator can copy the operation metadata into activity headers.

```go
func (p *OperationContextPropagator) InjectFromWorkflow(
    ctx workflow.Context,
    writer workflow.HeaderWriter,
) error {
    op, ok := OperationContextFromWorkflow(ctx)
    if !ok {
        return nil
    }

    payload, err := p.dataConverter.ToPayload(op)
    if err != nil {
        return err
    }

    writer.Set(operationContextHeader, payload)
    return nil
}
```

Flow:

```text
workflow.Context
      │
      ▼
InjectFromWorkflow()
      │
      ▼
Temporal Activity Header
```

---

# 15. Activity Extract

The activity worker receives a normal Go `context.Context`.

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

    if err := p.dataConverter.FromPayload(payload, &op); err != nil {
        return ctx, err
    }

    return WithOperationContext(ctx, op), nil
}
```

Now the activity receives:

```text
context.Context
│
├── hostname
├── correlation_id
├── orid
└── OTel SpanContext
```

---

# 16. Activity Example

```go
func MyActivity(
    ctx context.Context,
    input ActivityInput,
) error {
    logger := activity.GetLogger(ctx)
    logger.Info("activity started")

    return inventoryClient.Call(ctx, input)
}
```

The activity simply passes the same `context.Context` to downstream Go code.

---

# 17. Activity -> HTTP Client

No Temporal-specific mechanism is required here. Just pass `ctx`.

```go
func (c *InventoryClient) Call(
    ctx context.Context,
    input Request,
) error {
    slog.InfoContext(
        ctx,
        "calling inventory API",
    )

    return nil
}
```

The propagation pattern is:

```text
REST context.Context
       │
       ▼
workflow.Context
       │
       ▼
activity context.Context
       │
       ▼
HTTP client context.Context
```

---

# 18. OpenTelemetry Is a Separate Propagation Channel

Your custom context propagation and OpenTelemetry propagation are related, but separate.

```text
context.Context
│
├── OperationContext
│   ├── hostname
│   ├── correlation_id
│   └── orid
│
├── OTel SpanContext
│   ├── TraceID
│   └── SpanID
│
└── OTel Baggage
    ├── correlation_id
    └── orid
```

Temporal's OTel v2 plugin handles:

```text
TraceContext
+
Baggage
```

Your custom Temporal `ContextPropagator` handles:

```text
OperationContext
```

---

# 19. Do Not Use X-Correlation-ID as the OTel TraceID

Keep these separate.

Example:

```text
X-Correlation-ID
    CORR-184829

OpenTelemetry TraceID
    76ad31ee7627391ba452109f357c29fe
```

Use:

```text
TraceID
    technical distributed tracing identifier

CorrelationID
    application/request correlation identifier

ORID
    generated operation identifier
```

Let OpenTelemetry generate and manage TraceIDs.

---

# 20. Put correlation_id and orid in OTel Baggage

At the REST boundary:

```go
member1, err := baggage.NewMember(
    "correlation_id",
    op.CorrelationID,
)
if err != nil {
    return err
}

member2, err := baggage.NewMember(
    "orid",
    op.ORID,
)
if err != nil {
    return err
}
```

Then:

```go
bag := baggage.FromContext(ctx)

bag, err = bag.SetMember(member1)
if err != nil {
    return err
}

bag, err = bag.SetMember(member2)
if err != nil {
    return err
}

ctx = baggage.ContextWithBaggage(ctx, bag)
```

You may also add `hostname` to baggage if downstream services need it, but avoid putting sensitive information in baggage.

---

# 21. Baggage Does Not Automatically Become a Span Attribute

Baggage means:

```text
carry this information with the distributed operation
```

It does not automatically mean:

```text
display this value as an attribute on every span
```

At the REST boundary, explicitly annotate the current span:

```go
span := trace.SpanFromContext(ctx)

span.SetAttributes(
    attribute.String("hostname", op.Hostname),
    attribute.String("correlation_id", op.CorrelationID),
    attribute.String("orid", op.ORID),
)
```

So:

```text
Baggage
    = propagation

Span attributes
    = searchable trace metadata
```

---

# 22. OpenTelemetry Trace Flow

A single operation can look like:

```text
REST Server Span
TraceID = T1
SpanID  = S1

Temporal StartWorkflow Span
TraceID = T1
SpanID  = S2

Workflow Span
TraceID = T1
SpanID  = S3

Activity Span
TraceID = T1
SpanID  = S4

Outbound HTTP Span
TraceID = T1
SpanID  = S5
```

The TraceID remains the same while each span gets its own SpanID.

Your application metadata remains:

```text
correlation_id = C1
orid           = O1
hostname       = server01
```

---

# 23. Cleaner REST Setup

Centralize the operation setup.

```go
func BuildOperationContext(
    r *http.Request,
    hostname string,
) OperationContext {
    correlationID := r.Header.Get("X-Correlation-ID")

    if correlationID == "" {
        correlationID = uuid.NewString()
    }

    return OperationContext{
        Hostname:      hostname,
        CorrelationID: correlationID,
        ORID:          uuid.NewString(),
    }
}
```

Attach the operation metadata, baggage, and span attributes in one helper:

```go
func AttachOperationContext(
    ctx context.Context,
    op OperationContext,
) (context.Context, error) {
    ctx = WithOperationContext(ctx, op)

    correlationMember, err := baggage.NewMember(
        "correlation_id",
        op.CorrelationID,
    )
    if err != nil {
        return ctx, err
    }

    oridMember, err := baggage.NewMember(
        "orid",
        op.ORID,
    )
    if err != nil {
        return ctx, err
    }

    bag := baggage.FromContext(ctx)

    bag, err = bag.SetMember(correlationMember)
    if err != nil {
        return ctx, err
    }

    bag, err = bag.SetMember(oridMember)
    if err != nil {
        return ctx, err
    }

    ctx = baggage.ContextWithBaggage(ctx, bag)

    trace.SpanFromContext(ctx).SetAttributes(
        attribute.String("hostname", op.Hostname),
        attribute.String("correlation_id", op.CorrelationID),
        attribute.String("orid", op.ORID),
    )

    return ctx, nil
}
```

The handler becomes:

```go
func StartWorkflow(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    op := BuildOperationContext(
        r,
        request.Hostname,
    )

    ctx, err := AttachOperationContext(ctx, op)
    if err != nil {
        http.Error(
            w,
            err.Error(),
            http.StatusInternalServerError,
        )
        return
    }

    _, err = temporalClient.ExecuteWorkflow(
        ctx,
        client.StartWorkflowOptions{
            ID:        workflowID,
            TaskQueue: taskQueue,
        },
        MyWorkflow,
        request,
    )

    // handle response...
}
```

---

# 24. Downstream HTTP Calls

The activity passes the same context to the HTTP client:

```go
return ansibleClient.Launch(ctx, request)
```

The HTTP client:

```go
func (c *AnsibleClient) Launch(
    ctx context.Context,
    input LaunchRequest,
) error {
    slog.InfoContext(
        ctx,
        "calling ansible tower",
    )

    req, err := http.NewRequestWithContext(
        ctx,
        http.MethodPost,
        c.url,
        body,
    )
    if err != nil {
        return err
    }

    if op, ok := OperationContextFromContext(ctx); ok {
        req.Header.Set(
            "X-Correlation-ID",
            op.CorrelationID,
        )
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }

    defer resp.Body.Close()
    return nil
}
```

---

# 25. Instrument HTTP Client with OpenTelemetry

Use an OTel transport:

```go
httpClient := &http.Client{
    Transport: otelhttp.NewTransport(
        http.DefaultTransport,
    ),
}
```

Then create requests with the same context:

```go
req, err := http.NewRequestWithContext(
    ctx,
    http.MethodPost,
    url,
    body,
)
```

Conceptually, outbound headers become:

```http
traceparent: 00-76ad31...-2839...-01
baggage: correlation_id=CORR-123,orid=...
X-Correlation-ID: CORR-123
```

The first two are OTel/W3C propagation. `X-Correlation-ID` is your application-level header.

---

# 26. Why Explicitly Set X-Correlation-ID

Putting the correlation ID into baggage does not automatically create:

```http
X-Correlation-ID: ...
```

Baggage is normally propagated through the W3C `baggage` header.

If a downstream API expects `X-Correlation-ID`, set it explicitly.

```go
if op, ok := OperationContextFromContext(ctx); ok {
    req.Header.Set(
        "X-Correlation-ID",
        op.CorrelationID,
    )
}
```

---

# 27. Cleaner HTTP Header Helper

Avoid repeating the same code in every client.

```go
func ApplyCorrelationHeaders(
    ctx context.Context,
    req *http.Request,
) {
    op, ok := OperationContextFromContext(ctx)
    if !ok {
        return
    }

    if op.CorrelationID != "" {
        req.Header.Set(
            "X-Correlation-ID",
            op.CorrelationID,
        )
    }

    if op.ORID != "" {
        req.Header.Set(
            "X-ORID",
            op.ORID,
        )
    }
}
```

Then:

```go
req, err := http.NewRequestWithContext(
    ctx,
    http.MethodPost,
    url,
    body,
)
if err != nil {
    return err
}

ApplyCorrelationHeaders(ctx, req)
```

---

# 28. Cleaner Option: Custom RoundTripper

If many HTTP clients need the same headers, use a transport.

```go
type CorrelationTransport struct {
    Base http.RoundTripper
}

func (t *CorrelationTransport) RoundTrip(
    req *http.Request,
) (*http.Response, error) {
    base := t.Base
    if base == nil {
        base = http.DefaultTransport
    }

    cloned := req.Clone(req.Context())

    ApplyCorrelationHeaders(
        cloned.Context(),
        cloned,
    )

    return base.RoundTrip(cloned)
}
```

Compose it with OTel:

```go
baseTransport := &CorrelationTransport{
    Base: http.DefaultTransport,
}

httpClient := &http.Client{
    Transport: otelhttp.NewTransport(
        baseTransport,
    ),
}
```

Now outgoing requests automatically get application correlation headers plus OTel propagation.

---

# 29. Enrich slog Without Storing the Logger in Context

For normal application code, use:

```go
slog.InfoContext(
    ctx,
    "calling external API",
)
```

A custom `slog.Handler` can read the operation metadata and current span.

```go
type ContextHandler struct {
    next slog.Handler
}

func NewContextHandler(next slog.Handler) slog.Handler {
    return &ContextHandler{next: next}
}

func (h *ContextHandler) Enabled(
    ctx context.Context,
    level slog.Level,
) bool {
    return h.next.Enabled(ctx, level)
}

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

func (h *ContextHandler) WithAttrs(
    attrs []slog.Attr,
) slog.Handler {
    return &ContextHandler{
        next: h.next.WithAttrs(attrs),
    }
}

func (h *ContextHandler) WithGroup(
    name string,
) slog.Handler {
    return &ContextHandler{
        next: h.next.WithGroup(name),
    }
}
```

---

# 30. Logger Startup with Context Enrichment

```go
func configureLogging() {
    var level slog.LevelVar
    level.Set(slog.LevelInfo)

    baseHandler := slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            Level:     &level,
            AddSource: true,
        },
    )

    handler := NewContextHandler(baseHandler)
    logger := slog.New(handler)

    slog.SetDefault(logger)
}
```

Now normal application code can simply do:

```go
slog.InfoContext(
    ctx,
    "calling ansible tower",
)
```

and receive context/trace fields when available.

No logger needs to be stored in `context.Context`.

---

# 31. Enrich workflow.GetLogger()

Workflow code should stay:

```go
logger := workflow.GetLogger(ctx)
logger.Info("workflow started")
```

To automatically add:

```text
hostname
correlation_id
orid
```

use a Temporal worker interceptor.

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

Now `workflow.GetLogger(ctx).Info(...)` can be enriched automatically.

---

# 32. Enrich activity.GetLogger()

Do the equivalent for activities:

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

Now `activity.GetLogger(ctx).Info(...)` automatically includes the operation metadata.

---

# 33. Full End-to-End Flow

```text
Incoming REST request
│
├── X-Correlation-ID = C1
├── hostname = server01
└── generate ORID = O1
         │
         ▼
context.Context
│
├── OperationContext
│   ├── hostname = server01
│   ├── correlation_id = C1
│   └── orid = O1
│
├── OTel SpanContext
│   ├── TraceID = T1
│   └── SpanID = S1
│
└── OTel Baggage
    ├── correlation_id = C1
    └── orid = O1
         │
         ▼
ExecuteWorkflow(ctx)
         │
   ┌─────┴───────────┐
   │                 │
   ▼                 ▼
OTel v2         ContextPropagator
   │                 │
TraceContext      OperationContext
+ Baggage
   │                 │
   └────────┬────────┘
            ▼
      workflow.Context
            │
            ▼
      workflow.GetLogger()
            │
            ├── Temporal metadata
            ├── trace/span metadata
            └── hostname/correlation/orid
            │
            ▼
      ExecuteActivity(ctx)
            │
   ┌────────┴────────┐
   │                 │
   ▼                 ▼
OTel v2         ContextPropagator
   │                 │
   └────────┬────────┘
            ▼
       context.Context
            │
            ▼
      activity.GetLogger()
            │
            ├── Temporal metadata
            ├── trace/span metadata
            └── hostname/correlation/orid
            │
            ▼
       HTTP Client
            │
            ├── slog.InfoContext(ctx, ...)
            ├── traceparent
            ├── baggage
            ├── X-Correlation-ID
            └── X-ORID
            │
            ▼
       Downstream API
```

---

# 34. What Goes Where

| Value | OperationContext | OTel Baggage | Span Attribute | HTTP Header |
|---|---:|---:|---:|---:|
| hostname | Yes | Optional | Yes | Only if required |
| correlation_id | Yes | Yes | Yes | `X-Correlation-ID` |
| orid | Yes | Yes | Yes | Optional / `X-ORID` |
| trace_id | OTel handles | No | OTel handles | `traceparent` |
| span_id | OTel handles | No | OTel handles | `traceparent` |

---

# 35. Business Input vs Logging Context

If workflow logic actually needs `hostname`, keep it in the workflow input too.

```go
type WorkflowInput struct {
    Hostname string
    Action   string
}
```

Then also keep a copy in correlation metadata:

```go
OperationContext{
    Hostname:      input.Hostname,
    CorrelationID: correlationID,
    ORID:          orid,
}
```

The duplication is intentional:

```text
WorkflowInput
    = durable business input

OperationContext
    = cross-cutting logging / correlation metadata
```

Do not make workflow business logic depend only on context propagation.

---

# 36. Recommended Package Layout

```text
internal/
│
├── observability/
│   ├── context.go
│   ├── logging.go
│   ├── tracing.go
│   ├── temporal_propagator.go
│   └── temporal_interceptor.go
│
├── temporal/
│   ├── client.go
│   └── worker.go
│
├── httpclient/
│   ├── transport.go
│   └── ansible.go
│
└── api/
    └── handlers.go
```

Responsibilities:

```text
context.go
    OperationContext
    context helper functions

logging.go
    slog setup
    ContextHandler

tracing.go
    baggage
    span attributes
    OTel setup

temporal_propagator.go
    REST -> workflow -> activity propagation

temporal_interceptor.go
    workflow.GetLogger enrichment
    activity.GetLogger enrichment

transport.go
    X-Correlation-ID
    X-ORID
    otelhttp transport
```

---

# 37. Final Recommended Rules

## Logger

Create one base slog logger:

```go
slog.SetDefault(logger)
```

Do not store `*slog.Logger` in `context.Context`.

## Workflow

Use:

```go
workflow.GetLogger(ctx)
```

## Activity

Use:

```go
activity.GetLogger(ctx)
```

## Ordinary Go code

Use:

```go
slog.InfoContext(ctx, "...")
```

when operation-specific enrichment is required.

## Context

Store operation-scoped values such as:

```text
hostname
correlation_id
orid
```

## Temporal propagation

Use a `ContextPropagator` for `OperationContext`.

## OpenTelemetry propagation

Let Temporal OTel v2 propagate:

```text
TraceContext
Baggage
```

## Trace IDs

Do not replace the OTel TraceID with `X-Correlation-ID`.

Keep:

```text
trace_id
correlation_id
orid
```

as separate concepts.

## Baggage

Use baggage for values that should travel with the distributed trace, such as:

```text
correlation_id
orid
```

Do not assume baggage automatically becomes span attributes.

## Downstream HTTP calls

Use the same activity `context.Context`.

Let OTel propagate:

```text
traceparent
baggage
```

Explicitly add:

```text
X-Correlation-ID
```

if the downstream API expects it.

A custom `RoundTripper` is a clean way to do this automatically.

---

# 38. Final Mental Model

```text
slog.Default()
    = shared logger implementation

context.Context / workflow.Context
    = operation identity and metadata

Temporal ContextPropagator
    = custom metadata propagation

Temporal OTel v2
    = distributed trace propagation

slog ContextHandler
    = normal Go log enrichment

Temporal logger interceptor
    = workflow/activity log enrichment

HTTP RoundTripper
    = correlation header propagation
```

With this model, business code stays simple:

```go
// Workflow
workflow.GetLogger(ctx).
    Info("workflow started")
```

```go
// Activity
activity.GetLogger(ctx).
    Info("activity started")
```

```go
// Normal Go / HTTP client
slog.InfoContext(
    ctx,
    "calling external API",
)
```

The surrounding observability infrastructure handles propagation and enrichment automatically.
