# Temporal Batch Tracing Design
## OpenTelemetry + Splunk for Fan-In Batch Workflows

**Context:** Temporal Go workflows with a many-to-one-to-many topology:
- many independent VM workflows
- one batch coordinator
- one operation-specific Batch Execution Workflow per flushed batch
- one downstream shared execution, such as an Ansible Job ID
- progress/final status fan-out back to all original caller workflows

---

# 1. Problem

Tracing is simple while execution is sequential:

```text
HTTP request
    |
    v
Main Workflow
    |
    v
Activity
    |
    v
External API
```

Batching changes this.

```text
VM Workflow A ----\
VM Workflow B -----\
VM Workflow C ------> Batch Coordinator ---> Batch Execution
VM Workflow D -----/
```

Each VM workflow may already have its own trace:

```text
VM A -> Trace A
VM B -> Trace B
VM C -> Trace C
VM D -> Trace D
```

When the coordinator merges them, there is no single correct parent trace for the Batch Execution Workflow.

This is a **fan-in tracing problem**.

---

# 2. Correct OpenTelemetry model

Do not force all requests into one Trace ID.

Do not arbitrarily choose one VM request as the parent of the batch.

Instead:

1. each VM request keeps its own trace;
2. each flushed batch gets its own trace;
3. the batch root span contains **OpenTelemetry Span Links** to the spans that submitted each request.

```text
TRACE A                 TRACE B                 TRACE C
VM Workflow A           VM Workflow B           VM Workflow C
     |                       |                       |
     v                       v                       v
batch.submit A          batch.submit B          batch.submit C
     \                       |                       /
      \                      |                      /
       +---------------------+---------------------+
                             |
                        SPAN LINKS
                             |
                             v

                    TRACE BATCH-123
                  ansible.batch.execute
                             |
                             +-- launch
                             |
                             +-- poll
                             |
                             +-- poll
                             |
                             +-- SUCCESS
```

A span can have one parent but many links. Span Links are the right representation for batching, queues, asynchronous fan-in, and similar causal graphs.

---

# 3. Why the current traces look unrelated

Temporal tracing can propagate context through normal workflow/activity/signal operations.

For example:

```text
VM Workflow A
     |
     v
SignalExternalWorkflow
     |
     v
Batch Coordinator signal handling
```

However, once the coordinator stores the business request:

```go
bucket.Requests = append(bucket.Requests, req)
```

the incoming signal context is not automatically stored with that request.

Later:

```go
workflow.ExecuteChildWorkflow(
    ctx,
    AnsibleBatchExecutionWorkflow,
    batch,
)
```

the child is started from the coordinator's current workflow context.

The coordinator may have accepted requests from:

```text
Trace A
Trace B
Trace C
Trace D
```

There is no single correct parent.

Therefore the Batch Execution Workflow commonly appears in Splunk as a separate trace unless links are created explicitly.

---

# 4. Desired topology

```text
REQUEST TRACE A
==================================================

VM01 Workflow
     |
     +-- resolve
     |
     +-- ansible.batch.submit
              |
              | TraceRef A
              +--------------------------+
                                         |
REQUEST TRACE B                          |
==================================================
                                         |
VM02 Workflow                            |
     |                                   |
     +-- resolve                         |
     |                                   |
     +-- ansible.batch.submit            |
              |                          |
              | TraceRef B               |
              +----------------------+   |
                                     |   |
                                     v   v

BATCH TRACE
==================================================

ansible.batch.execute
    |
    | links:
    |   Trace A / Submit Span A
    |   Trace B / Submit Span B
    |   Trace C / Submit Span C
    |
    +-- launch Ansible
    |
    +-- poll #1 RUNNING
    |
    +-- poll #2 RUNNING
    |
    +-- poll #3 SUCCESS
```

The batch is a separate trace, but it is causally connected to every contributing request trace.

---

# 5. Carry trace context explicitly

Serialize a small trace reference into each batch request.

Do not carry:
- a live OpenTelemetry span;
- `context.Context`;
- Temporal workflow context.

Carry only immutable tracing identifiers.

```go
type TraceRef struct {
    TraceID string
    SpanID  string

    TraceFlags byte
    TraceState string
}
```

Add it to the request:

```go
type BatchRequest struct {
    RequestID string

    CallerWorkflowID string

    VM string

    Trace TraceRef
}
```

Because this is part of Temporal state/history, it survives:
- worker restart;
- replay;
- coordinator waiting;
- timers;
- Continue-As-New;
- delayed batch formation.

---

# 6. Capture trace context at `batch.submit`

Create a dedicated span immediately before signaling the coordinator.

```text
VM Workflow
    |
    +-- resolve target
    |
    +-- ansible.batch.submit  <-- capture this span
            |
            +-- SignalExternalWorkflow(...)
```

This gives the batch a precise causal reference: the point where that request entered batching.

---

# 7. Submission span example

Using Temporal's workflow-safe OpenTelemetry tracer:

```go
import (
    temporalotel "go.temporal.io/sdk/contrib/opentelemetry-v2"
)
```

Conceptual implementation:

```go
func submitToAnsibleBatch(
    ctx workflow.Context,
    req BatchRequest,
) error {
    tracer := temporalotel.Tracer("vm-workflow")

    submitCtx, span := tracer.Start(
        ctx,
        "ansible.batch.submit",
    )
    defer span.End()

    sc := span.SpanContext()

    req.Trace = TraceRef{
        TraceID:    sc.TraceID().String(),
        SpanID:     sc.SpanID().String(),
        TraceFlags: byte(sc.TraceFlags()),
        TraceState: sc.TraceState().String(),
    }

    return workflow.SignalExternalWorkflow(
        submitCtx,
        "batch:ansible",
        "",
        "submit",
        req,
    ).Get(submitCtx, nil)
}
```

The important part is:

```text
req.Trace
```

The trace reference is explicitly persisted with the business request.

---

# 8. Coordinator behavior

The coordinator should preserve the TraceRef unchanged.

```text
Batch Bucket

Request R001
  VM = VM01
  TraceRef = Trace-A / Span-A

Request R002
  VM = VM02
  TraceRef = Trace-B / Span-B

Request R003
  VM = VM03
  TraceRef = Trace-C / Span-C
```

When the bucket flushes:

```go
type AnsibleBatchExecutionInput struct {
    BatchExecutionID string
    Requests         []AnsibleBatchRequest
}
```

Every request still contains its source `TraceRef`.

---

# 9. Do not use the coordinator as the business trace parent

The coordinator is infrastructure:

```text
batch:ansible
```

It may:
- live indefinitely;
- Continue-As-New repeatedly;
- process thousands of unrelated requests;
- receive signals from many traces.

Do not create one giant coordinator business trace.

Prefer:

```text
Request Trace A
Request Trace B
Request Trace C

        |
        | Span Links
        v

Batch Trace B123
```

---

# 10. Reconstruct SpanContext

In the Batch Execution Workflow:

```go
func restoreSpanContext(
    ref TraceRef,
) (trace.SpanContext, error) {
    traceID, err := trace.TraceIDFromHex(ref.TraceID)
    if err != nil {
        return trace.SpanContext{}, err
    }

    spanID, err := trace.SpanIDFromHex(ref.SpanID)
    if err != nil {
        return trace.SpanContext{}, err
    }

    traceState, err := trace.ParseTraceState(ref.TraceState)
    if err != nil {
        return trace.SpanContext{}, err
    }

    return trace.NewSpanContext(
        trace.SpanContextConfig{
            TraceID:    traceID,
            SpanID:     spanID,
            TraceFlags: trace.TraceFlags(ref.TraceFlags),
            TraceState: traceState,
            Remote:     true,
        },
    ), nil
}
```

---

# 11. Build Span Links

```go
links := make(
    []trace.Link,
    0,
    len(input.Requests),
)

for _, req := range input.Requests {
    sc, err := restoreSpanContext(req.Trace)
    if err != nil {
        continue
    }

    links = append(
        links,
        trace.Link{
            SpanContext: sc,
            Attributes: []attribute.KeyValue{
                attribute.String(
                    "request.id",
                    req.RequestID,
                ),
                attribute.String(
                    "caller.workflow.id",
                    req.CallerWorkflowID,
                ),
                attribute.String(
                    "vm",
                    req.VM,
                ),
            },
        },
    )
}
```

The link attributes make navigation and troubleshooting easier.

---

# 12. Start a new root batch trace

The batch execution should intentionally start a new trace:

```go
tracer := temporalotel.Tracer(
    "batch-execution",
)

batchCtx, span := tracer.Start(
    ctx,
    "ansible.batch.execute",

    trace.WithNewRoot(),

    trace.WithLinks(
        links...,
    ),

    trace.WithAttributes(
        attribute.String(
            "batch.execution.id",
            input.BatchExecutionID,
        ),
        attribute.Int(
            "batch.size",
            len(input.Requests),
        ),
    ),
)

defer span.End()
```

The separate Trace ID is expected and correct.

---

# 13. Use `batchCtx` for downstream work

Do:

```go
workflow.ExecuteActivity(
    batchCtx,
    LaunchAnsibleBatchActivity,
    input,
)
```

and:

```go
workflow.ExecuteActivity(
    batchCtx,
    GetAnsibleStatusActivity,
    jobID,
)
```

Do not accidentally fall back to the original `ctx` if the batch trace should be the parent.

Desired trace:

```text
TRACE BATCH-123

ansible.batch.execute
    |
    +-- LaunchAnsibleBatch
    |
    +-- PollAnsible #1
    |
    +-- PollAnsible #2
    |
    +-- PollAnsible #3
```

---

# 14. Recommended batch attributes

```text
batch.execution.id
batch.size
provider
operation

ansible.environment
ansible.template.type
ansible.template.id
ansible.job.id

temporal.workflow.id
temporal.run.id
```

Do not add secrets.

---

# 15. Recommended request attributes

```text
request.id
caller.workflow.id
vm
operation
provider
batch.execution.id   // once known
```

The caller may learn the `BatchExecutionID` only after receiving a later status Signal.

---

# 16. Stable correlation identifiers

Use these consistently.

## Request ID

One logical VM-level request:

```text
request.id = vm123:patch:2026-10
```

## Batch Execution ID

One flushed multi-VM batch:

```text
batch.execution.id = B123
```

## External Execution ID

Provider-side execution:

```text
external.execution.id = Ansible Job ID
```

or:

```text
external.execution.id = Qualys Scan ID
```

These identifiers should appear in:
- logs;
- span attributes;
- status signals;
- error diagnostics.

---

# 17. Centralized polling trace

The Batch Execution Workflow owns the external Job ID.

```text
TRACE BATCH-123

ansible.batch.execute
       |
       +-- launch
       |     |
       |     +-- job.id = J456
       |
       +-- poll #1
       |     |
       |     +-- RUNNING
       |
       +-- poll #2
       |     |
       |     +-- RUNNING
       |
       +-- poll #3
             |
             +-- SUCCESS
```

The caller workflows do not create separate polling spans.

---

# 18. Status Signal payload

Example:

```go
type BatchStatusSignal struct {
    RequestID string

    BatchExecutionID string

    ExternalExecutionID string

    State string

    PollSequence int
    LastPolledAt time.Time

    Message string

    // Optional: used for a reverse link from caller
    // status-handling spans back to the batch trace.
    BatchTrace TraceRef
}
```

---

# 19. Caller-side status tracing

Non-terminal:

```text
batch-status: RUNNING
       |
       v
batch.status.received
       |
       +-- log
       |
       +-- wait again
```

Terminal:

```text
batch-status: SUCCESS
       |
       v
batch.status.received
       |
       +-- continue workflow
```

The caller remains part of its own request trace.

Do not make the rest of the caller workflow a child of the batch trace.

---

# 20. Optional reverse Span Link

For richer navigation:

```text
REQUEST TRACE
   |
   +-- batch.status.received
             |
             +---- Span Link ----> Batch Trace
```

Then the relationship is visible in both conceptual directions:

```text
Batch Trace
   +---- links ---> Request traces

Request status spans
   +---- links ---> Batch trace
```

---

# 21. Attributes are not a replacement for Span Links

This is useful:

```text
batch.execution.id = B123
```

But it does not create an OpenTelemetry causal relationship.

Use both:

```text
Span Links
+
correlation attributes
```

Span Links provide causality.

Correlation attributes provide searchability.

---

# 22. What to expect in Splunk

Open:

```text
ansible.batch.execute
```

Expected:

```text
Attributes
--------------------------------
batch.execution.id = B123
batch.size = 10
ansible.job.id = J456


Span Links
--------------------------------

Trace A / Span A
request.id = R001
workflow.id = VM01

Trace B / Span B
request.id = R002
workflow.id = VM02

Trace C / Span C
request.id = R003
workflow.id = VM03
```

The traces remain separate.

That is correct.

The links are the relationship.

---

# 23. Diagnostic checklist

If the Batch Execution trace appears unrelated:

- [ ] Every batch request contains a valid `TraceRef`.
- [ ] The captured Span ID belongs to `batch.submit`.
- [ ] Coordinator preserves TraceRef unchanged.
- [ ] Batch Execution input contains all request TraceRefs.
- [ ] Trace IDs and Span IDs reconstruct successfully.
- [ ] Batch root span uses `trace.WithLinks(...)`.
- [ ] Batch root span is exported.
- [ ] `batchCtx` is used for launch/poll Activities.
- [ ] Splunk shows a Links section on `ansible.batch.execute`.
- [ ] Sampling retains the batch root trace.
- [ ] Malformed TraceRefs are logged.
- [ ] Link count is within configured OTel/Splunk limits.

---

# 24. Sampling

The batch span is a new root:

```go
trace.WithNewRoot()
```

So parent-based sampling does not inherit a decision from one of the source traces.

Example:

```text
Request Trace A -> sampled
Request Trace B -> sampled
Request Trace C -> sampled

Batch Trace -> independent sampling decision
```

If the batch trace is dropped, its links disappear too.

For important infrastructure batch traces, consider:
- always sampling them; or
- giving them a high-retention sampling policy.

---

# 25. Preserve TraceFlags

Keep:

```go
TraceFlags byte
```

and restore:

```go
TraceFlags: trace.TraceFlags(ref.TraceFlags)
```

This preserves source span sampling metadata in the link context.

---

# 26. Preserve TraceState

Keep:

```go
TraceState string
```

and reconstruct with:

```go
trace.ParseTraceState(...)
```

This is useful when distributed tracing metadata depends on tracestate.

---

# 27. Continue-As-New in coordinator

Because TraceRef is part of each pending request, it naturally survives coordinator Continue-As-New.

```text
Coordinator Run A

R001 -> Trace A / Span A
R002 -> Trace B / Span B

Continue-As-New
       |
       v

Coordinator Run B

R001 -> Trace A / Span A
R002 -> Trace B / Span B
```

No extra tracing propagation is needed beyond carrying workflow state.

---

# 28. Continue-As-New in Batch Execution

For a very long-running job:

```text
Workflow ID:
batch-exec:ansible:B123

Run 1
   |
   | Job J456
   |
   +-- Continue-As-New
           |
           v
Run 2
   |
   | same BatchExecutionID
   | same Job J456
   |
   +-- continue polling
```

Carry:

```text
BatchExecutionID
ExternalExecutionID
Request list
Request TraceRefs
PollSequence
Last status
```

Do not relaunch the provider operation.

Always retain:

```text
batch.execution.id
external.execution.id
```

as stable searchable correlation attributes.

---

# 29. Coordinator telemetry

Treat coordinator tracing as operational telemetry.

Useful low-level events/spans:

```text
batch.request.accepted
batch.bucket.created
batch.bucket.flushed
batch.execution.started
batch.request.deduplicated
```

Do not turn `batch:ansible` into one huge business trace.

---

# 30. Recommended span names

Request side:

```text
vm.workflow
ansible.resolve-target
ansible.batch.submit
batch.status.received
```

Batch side:

```text
ansible.batch.execute
ansible.batch.launch
ansible.batch.poll
```

ODST:

```text
odst.batch.execute
odst.scan.launch
odst.scan.poll
```

DMS:

```text
dms.batch.execute
dms.boks.remove-host-group
```

Keep span names low-cardinality.

Use attributes for VM IDs, Job IDs, Batch IDs, and Request IDs.

---

# 31. Logging correlation

Use the same correlation identifiers in logs.

```go
logger.Info(
    "Ansible batch status",
    "request.id", status.RequestID,
    "batch.execution.id", status.BatchExecutionID,
    "external.execution.id", status.ExternalExecutionID,
    "state", status.State,
    "poll.sequence", status.PollSequence,
)
```

In Splunk, searching:

```text
batch.execution.id=B123
```

should show:
- Batch Execution logs;
- launch logs;
- poll logs;
- status fan-out logs;
- caller status logs.

This complements Span Links.

---

# 32. Error tracing

If launch fails:

```text
ansible.batch.execute
    |
    +-- ansible.batch.launch ERROR
```

Record:

```text
batch.execution.id
template.id
environment
error.type
```

Then signal failure to callers.

For per-host business failures, distinguish:

```text
integration/system error
```

from:

```text
business/host result failure
```

A Batch Execution Workflow can complete normally while individual host results contain failures.

---

# 33. Fan-out tracing

The batch later sends status to existing workflows:

```text
Batch Trace
     |
     +-- signal A
     +-- signal B
     +-- signal C
```

Do not make those caller traces children of the batch trace.

They existed before the batch.

The correct structure is a graph:

```text
Trace A ---\
Trace B ----\
Trace C -----> Batch Trace
Trace D ----/       |
                   /|\
                  / | \
                 v  v  v
              status back
```

Span Links model this without corrupting parent-child semantics.

---

# 34. Why one giant trace is incorrect

Forcing VM A, B, and C under one Trace ID implies they are one original request or one caused another.

That is false.

They are independent requests that later share a batch optimization.

Therefore:

```text
separate traces + span links
```

is more accurate than:

```text
one giant trace
```

---

# 35. Implementation sequence

1. Add `TraceRef` to the batch request.
2. Create explicit `batch.submit` spans in VM workflows.
3. Capture their SpanContext.
4. Put TraceRef in the Signal payload.
5. Preserve TraceRef in coordinator bucket state.
6. Pass requests unchanged into Batch Execution Workflow.
7. Reconstruct source SpanContexts.
8. Build `[]trace.Link`.
9. Start a new root batch span with `trace.WithLinks`.
10. Use `batchCtx` for all child Activities.
11. Add `batch.execution.id` everywhere.
12. Add `external.execution.id` after launch.
13. Optionally include BatchTrace `TraceRef` in status Signals.
14. Optionally create `batch.status.received` spans with reverse links.
15. Verify Splunk displays Span Links.
16. Review batch-trace sampling.

---

# 36. Minimal end-to-end pseudo-code

## VM workflow

```go
func submit(
    ctx workflow.Context,
    req BatchRequest,
) error {
    tracer := temporalotel.Tracer(
        "vm-workflow",
    )

    submitCtx, span := tracer.Start(
        ctx,
        "ansible.batch.submit",
    )
    defer span.End()

    sc := span.SpanContext()

    req.Trace = TraceRef{
        TraceID:    sc.TraceID().String(),
        SpanID:     sc.SpanID().String(),
        TraceFlags: byte(sc.TraceFlags()),
        TraceState: sc.TraceState().String(),
    }

    return workflow.SignalExternalWorkflow(
        submitCtx,
        "batch:ansible",
        "",
        "submit",
        req,
    ).Get(submitCtx, nil)
}
```

## Coordinator

```go
func accept(
    state *CoordinatorState,
    req BatchRequest,
) {
    state.Buckets[key].Requests =
        append(
            state.Buckets[key].Requests,
            req,
        )
}
```

The TraceRef simply travels with the request.

## Batch Execution Workflow

```go
func AnsibleBatchExecutionWorkflow(
    ctx workflow.Context,
    input AnsibleBatchExecutionInput,
) error {
    links := make(
        []trace.Link,
        0,
        len(input.Requests),
    )

    for _, req := range input.Requests {
        sc, err := restoreSpanContext(
            req.Trace,
        )
        if err != nil {
            workflow.GetLogger(ctx).Warn(
                "Invalid request trace reference",
                "request.id",
                req.RequestID,
            )
            continue
        }

        links = append(
            links,
            trace.Link{
                SpanContext: sc,
                Attributes: []attribute.KeyValue{
                    attribute.String(
                        "request.id",
                        req.RequestID,
                    ),
                },
            },
        )
    }

    tracer := temporalotel.Tracer(
        "batch-execution",
    )

    batchCtx, span := tracer.Start(
        ctx,
        "ansible.batch.execute",
        trace.WithNewRoot(),
        trace.WithLinks(links...),
        trace.WithAttributes(
            attribute.String(
                "batch.execution.id",
                input.BatchExecutionID,
            ),
            attribute.Int(
                "batch.size",
                len(input.Requests),
            ),
        ),
    )
    defer span.End()

    var launch AnsibleLaunchResult

    if err := workflow.ExecuteActivity(
        batchCtx,
        LaunchAnsibleBatchActivity,
        input,
    ).Get(
        batchCtx,
        &launch,
    ); err != nil {
        return err
    }

    // Continue centralized polling using batchCtx.
    return nil
}
```

---

# 37. Splunk verification procedure

After deployment:

1. Trigger two or more VM workflows that enter the same batch.
2. Open one VM trace.
3. Confirm `ansible.batch.submit` exists.
4. Record its Trace ID and Span ID.
5. Open the corresponding batch trace.
6. Open `ansible.batch.execute`.
7. Find the Span Links section.
8. Confirm one link exists per batch request.
9. Navigate a link.
10. Verify Splunk opens the corresponding source trace/span.
11. Search `batch.execution.id=<ID>`.
12. Confirm batch and caller logs correlate.
13. Confirm Ansible polling spans are children of the batch trace.
14. Confirm VM workflows do not create independent Ansible poll spans.

If the batch root has no links, verify that `trace.WithLinks(...)` is actually passed when the span is created.

---

# 38. Final model

```text
                    REQUEST TRACES

Trace A                     Trace B
+------------------+       +------------------+
| VM Workflow A    |       | VM Workflow B    |
|                  |       |                  |
| batch.submit A   |       | batch.submit B   |
+--------+---------+       +--------+---------+
         \                          /
          \                        /
           \      SPAN LINKS      /
            \                    /
             v                  v

                  BATCH TRACE

          +--------------------------+
          | ansible.batch.execute    |
          |                          |
          | batch.execution.id=B123  |
          | batch.size=10            |
          +------------+-------------+
                       |
                       +-- launch
                       |
                       +-- poll RUNNING
                       |
                       +-- poll RUNNING
                       |
                       +-- poll SUCCESS
                       |
                  +----+-----+
                  |          |
             status A     status B
                  |          |
                  v          v

             REQUEST TRACES CONTINUE

Trace A                     Trace B
+------------------+       +------------------+
| status RUNNING   |       | status RUNNING   |
| log + wait       |       | log + wait       |
|                  |       |                  |
| status SUCCESS   |       | status SUCCESS   |
| continue         |       | continue         |
+------------------+       +------------------+
```

The separate traces are intentional.

The missing relationship is represented by:

```text
OpenTelemetry Span Links
```

and operational correlation is provided by:

```text
request.id
batch.execution.id
external.execution.id
```

Together they provide the most accurate representation of the Temporal fan-in/fan-out architecture in Splunk.
