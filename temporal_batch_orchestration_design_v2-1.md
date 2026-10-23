# Temporal Batch Orchestration Design
## Ansible, ODST/Qualys, and DMS/BoKS

**Status:** Proposed implementation design  
**Language/SDK:** Go + Temporal Go SDK  
**Primary goal:** Batch VM-level operations into efficient multi-server downstream calls while preserving per-VM workflow isolation, durability, idempotency, observability, and bounded Temporal history.

---

## 1. Executive summary

The system has many independent VM workflows. Each VM workflow may need to perform operations through one of three integration families:

1. **Ansible**
   - Patch
   - Scan
   - Privilege removal
   - Two Ansible environments: **Primary** and **Secondary**
   - Routing is based on VM environment and VM domain.
   - Primary and Secondary each have their own configuration that maps:
     - `operation -> domain -> template`
   - Patch and scan use **Ansible Job Templates**.
   - Privilege removal uses **Ansible Workflow Job Templates**.
   - A single Ansible launch can contain multiple VMs.

2. **ODST**
   - Primarily used to trigger **Qualys scans**.
   - A single compatible ODST/Qualys request should contain multiple VMs where possible.

3. **DMS**
   - Calls **BoKS** APIs.
   - Current batching use case is removal of host groups from multiple servers.
   - Requests can only share a batch when the common BoKS/DMS request parameters are compatible.

The recommended architecture uses **three long-running Batch Coordinator Workflows**:

```text
batch:ansible
batch:odst
batch:dms
```

Each coordinator owns multiple **internal buckets**. A bucket contains requests that can be represented by exactly one downstream operation.

When a bucket reaches its configured maximum batch size, or its maximum wait deadline expires, the coordinator creates a **Batch Execution Workflow** for that batch. The Batch Execution Workflow owns the downstream Job/Scan/Operation ID, polls that external execution **once for the entire batch**, and fans status back to every originating VM workflow. Callers can therefore receive `PENDING`/`RUNNING` progress notifications for logging while only `SUCCESS`/`FAILED`/other terminal states release them to continue their business flow. Individual VM workflows never poll the same downstream Job ID independently.

This separation is important:

```text
VM Workflow
    |
    | submit one logical request
    v
Batch Coordinator
    |
    | aggregate compatible requests
    v
Batch Execution Workflow
    |
    | one downstream multi-VM operation
    v
Ansible / ODST / DMS
    |
    | monitor once
    v
Signal individual results
    |
    +------> VM Workflow A
    +------> VM Workflow B
    +------> VM Workflow C
```

The design intentionally separates:

- **routing/config resolution**
- **batch formation**
- **batch execution**
- **external idempotency**
- **result fan-out**
- **request deduplication**
- **history management**

---

# 2. Core design decisions

The recommended decisions are:

| Concern | Decision |
|---|---|
| Number of top-level batch coordinators | 3 |
| Ansible coordinator | One workflow: `batch:ansible` |
| ODST coordinator | One workflow: `batch:odst` |
| DMS coordinator | One workflow: `batch:dms` |
| Ansible batching boundary | Resolved Ansible environment + template type + template ID + compatible common launch parameters |
| ODST batching boundary | Compatible Qualys/ODST scan configuration |
| DMS batching boundary | Compatible BoKS/DMS operation parameters, such as host group |
| Batch trigger | Maximum size OR maximum wait time |
| Long-running execution | Separate Batch Execution Workflow |
| External status polling | Poll once per Batch Execution Workflow, never once per VM workflow |
| Progress notification | Batch Execution Workflow fans status signals to all callers |
| Caller behavior for non-terminal state | Log/update progress and wait again |
| Caller behavior for terminal state | Resume success/failure business flow |
| Unchanged RUNNING notifications | Supported every poll; recommended to throttle/heartbeat for history efficiency |
| Request correlation | Stable `RequestID` |
| Batch correlation | Deterministic `BatchExecutionID` |
| Request deduplication | `RequestID`, not Workflow ID alone |
| Batch deduplication | `BatchExecutionID` + Workflow ID reuse protection + downstream idempotency |
| Worker/app restart | Temporal replay reconstructs workflow state |
| Workflow history growth | `Continue-As-New` |
| Continue-As-New | Prefer idle rollover; support state-carrying rollover when required |
| Signals before Continue-As-New | Drain signal channel using `ReceiveAsync` immediately before continuing |
| Timers | Temporal workflow timers only |
| External I/O | Activities only |
| Configuration reads | Activities, not direct reads in Workflow code |
| Configuration changes | Resolve to immutable target + include configuration/fingerprint information in batch compatibility |
| Native Go goroutines/channels/timers | Do not use inside Workflow code |

---

# 3. System-level architecture

```text
+--------------------------------------------------------------------------+
|                              TEMPORAL                                    |
|                                                                          |
|  +------------------+     +------------------+     +------------------+   |
|  | VM Workflow A    |     | VM Workflow B    |     | VM Workflow N    |   |
|  +--------+---------+     +--------+---------+     +---------+--------+   |
|           |                        |                         |             |
|           | operation request      |                         |             |
|           +------------------------+-------------------------+             |
|                                    |                                       |
|                                    v                                       |
|                         Resolve target/config                              |
|                              Activity                                      |
|                                    |                                       |
|                   +----------------+----------------+                      |
|                   |                |                |                      |
|                   v                v                v                      |
|              ANSIBLE request    ODST request     DMS request               |
|                   |                |                |                      |
|                   v                v                v                      |
|           +---------------+ +---------------+ +---------------+            |
|           | batch:ansible | |  batch:odst   | |   batch:dms   |            |
|           | Coordinator   | | Coordinator   | | Coordinator   |            |
|           +-------+-------+ +-------+-------+ +-------+-------+            |
|                   |                 |                 |                    |
|            internal buckets  internal buckets  internal buckets            |
|                   |                 |                 |                    |
|                   +--------+--------+--------+--------+                    |
|                            |                 |                             |
|                     bucket ready      bucket ready                         |
|                            |                 |                             |
|                            v                 v                             |
|                +----------------------+                                     |
|                | BatchExecutionWorkflow|  one per flushed batch            |
|                +----------+-----------+                                     |
|                           |                                                 |
|                           v                                                 |
|                     Provider Activities                                    |
+---------------------------+------------------------------------------------+
                            |
          +-----------------+-------------------+
          |                 |                   |
          v                 v                   v
   Primary/Secondary      ODST / Qualys        DMS / BoKS
       Ansible
```

---

# 4. Why three coordinators instead of one generic coordinator

A fully generic coordinator is technically possible, but three integration-specific coordinators provide a cleaner operational boundary.

```text
                    BATCHING SUBSYSTEM

           +-------------+-------------+
           |             |             |
           v             v             v
       ANSIBLE          ODST          DMS
       batching         batching      batching
```

Benefits:

- failures in ODST batching do not affect Ansible batching state;
- DMS traffic cannot increase Ansible coordinator history;
- separate dashboards and metrics are straightforward;
- separate deployment/task-queue scaling can be introduced later;
- provider-specific bucket keys remain easy to understand;
- Continue-As-New occurs independently;
- troubleshooting is simpler.

The batching algorithm can still be implemented through shared Go helper code where useful. The Temporal Workflow functions themselves should remain explicit enough to be observable and maintainable.

---

# 5. Ansible configuration model

There are three relevant pieces of configuration.

## 5.1 Routing configuration

The routing configuration determines whether a VM operation goes to Primary or Secondary Ansible.

Conceptually:

```text
VM Environment
    +
VM Domain
    |
    v
Routing Config
    |
    v
PRIMARY or SECONDARY
```

Example:

```text
routing:
  PROD:
    domainA: PRIMARY
    domainB: SECONDARY

  NONPROD:
    domainA: SECONDARY
    domainB: SECONDARY
```

The exact configuration representation is not important to the batching architecture.

---

## 5.2 Primary Ansible configuration

Conceptual hierarchy:

```text
operation
   |
 domain
   |
template
```

Example:

```text
PRIMARY

patch
 +-- domainA -> Job Template 101
 +-- domainB -> Job Template 102

scan
 +-- domainA -> Job Template 201
 +-- domainB -> Job Template 202

privilege-removal
 +-- domainA -> Workflow Job Template 301
 +-- domainB -> Workflow Job Template 302
```

---

## 5.3 Secondary Ansible configuration

Example:

```text
SECONDARY

patch
 +-- domainA -> Job Template 501
 +-- domainB -> Job Template 502

scan
 +-- domainA -> Job Template 601
 +-- domainB -> Job Template 602

privilege-removal
 +-- domainA -> Workflow Job Template 701
 +-- domainB -> Workflow Job Template 702
```

Primary and Secondary may contain different template IDs and potentially different common launch configuration.

---

# 6. Resolve first, batch second

The VM workflow should not submit:

```text
PROD + domainA + PATCH
```

directly to a batch bucket.

It should first resolve that business request into the exact downstream execution target.

```text
VM Workflow
    |
    | VM = vm001
    | VM Environment = PROD
    | Domain = domainA
    | Operation = PATCH
    v
ResolveAnsibleTargetActivity
    |
    +-- read routing config
    |      |
    |      +--> PRIMARY
    |
    +-- read PRIMARY Ansible config
           |
           +--> patch.domainA.template
                    |
                    +--> Job Template 101
    |
    v
ResolvedAnsibleTarget
```

Result:

```text
Provider          = ansible
AnsibleEnvironment= primary
TemplateType      = job-template
TemplateID        = 101
CommonParams      = ...
CompatibilityHash = ...
ConfigRevision    = ...
```

The resolved value is returned from an Activity and therefore becomes recorded in Temporal Workflow History.

This has two important properties:

1. **Replay does not re-read changing configuration.**
2. A request retains the execution decision that existed when it was resolved.

---

# 7. Why configuration must not be read directly from Workflow code

Temporal Workflow code is replayed.

Do not do this inside Workflow code:

```go
os.Getenv("ANSIBLE_ROUTING_CONFIG")
os.ReadFile(...)
http.Get(...)
database.Query(...)
time.Now()
```

A replay could observe different values and take a different execution path.

External I/O and configuration reads belong in Activities.

Workflow code should use deterministic inputs and results already recorded by Temporal.

Use:

```text
Workflow
   |
   v
Activity: ResolveAnsibleTarget
   |
   v
recorded result
```

instead of:

```text
Workflow
   |
   +--> environment variables
   +--> filesystem
   +--> database
```

---

# 8. Resolved Ansible target

A practical Go model could look like:

```go
type AnsibleTemplateType string

const (
    AnsibleJobTemplate      AnsibleTemplateType = "job-template"
    AnsibleWorkflowTemplate AnsibleTemplateType = "workflow-template"
)

type AnsibleEnvironment string

const (
    AnsiblePrimary   AnsibleEnvironment = "primary"
    AnsibleSecondary AnsibleEnvironment = "secondary"
)

type ResolvedAnsibleTarget struct {
    Environment AnsibleEnvironment

    TemplateType AnsibleTemplateType
    TemplateID   int64

    // Version or revision of the configuration used for resolution.
    ConfigRevision string

    // Canonical hash of fields that MUST be identical for VMs
    // to share one downstream launch.
    CompatibilityHash string

    // Do not place passwords/tokens here.
    // Only non-secret, execution-defining values should be carried
    // through workflow history.
}
```

Do not put Ansible passwords, OAuth tokens, API keys, or other secrets in Workflow inputs, Signals, or Workflow state.

Activities should obtain credentials from the runtime secret provider.

---

# 9. The real batching rule

The batching rule is:

> Two requests may share a batch only when they can be represented by one downstream API request without changing the meaning of either operation.

For Ansible:

```text
same Ansible environment
+
same template type
+
same template ID
+
same common launch parameters
=
same batch bucket
```

The VM itself is normally the varying field.

Example:

```text
TemplateID: 101
Inventory: PROD
Credential: Linux
Shared extra-vars: X
Servers:
    vm001
    vm002
    vm003
```

The common fields belong in the batch compatibility identity. The server list does not.

---

# 10. Ansible BatchKey

Recommended structure:

```go
type AnsibleBatchKey struct {
    Environment       AnsibleEnvironment
    TemplateType      AnsibleTemplateType
    TemplateID        int64
    CompatibilityHash string
}
```

Canonical string form:

```text
primary|job-template|101|sha256:ABC...
```

or:

```text
secondary|workflow-template|701|sha256:DEF...
```

The compatibility hash should be generated from a canonical representation of every common parameter that must match across the downstream request.

Do not hash ordinary Go map serialization unless canonical ordering is guaranteed.

Use a deterministic canonical structure.

Example:

```text
Compatibility fields:
- inventory ID
- organization ID, if relevant
- credential selection, if common
- execution environment, if common
- common extra-vars
- limit semantics
- configuration revision when required
```

If different values can safely coexist per VM in the downstream API, those fields should not be in the compatibility hash.

---

# 11. Domain and VM environment are routing inputs, not automatically batch keys

Suppose:

```text
VM A:
  environment = PROD
  domain = domainA
  operation = PATCH

VM B:
  environment = NONPROD
  domain = domainB
  operation = PATCH
```

If both resolve to:

```text
PRIMARY
Job Template 101
same common launch parameters
```

then they may be batched together.

```text
              PRIMARY / JOB / 101

             +-----------------+
             | vmA             |
             | vmB             |
             +-----------------+
```

Do not artificially separate requests merely because their original routing inputs differ.

The downstream compatibility determines the batch boundary.

---

# 12. Job templates vs Workflow Job Templates

Patch and scan use Job Templates.

Privilege removal uses Workflow Job Templates.

The batch coordinator should not need separate high-level logic for these.

The template type is part of the resolved target:

```text
                 Ansible target
                      |
             +--------+--------+
             |                 |
             v                 v
      Job Template       Workflow Template
             |                 |
      patch / scan       privilege removal
```

The execution layer chooses the appropriate Ansible API.

Conceptually:

```go
switch target.TemplateType {
case AnsibleJobTemplate:
    return launchJobTemplate(...)

case AnsibleWorkflowTemplate:
    return launchWorkflowTemplate(...)
}
```

---

# 13. ODST / Qualys batching

ODST is primarily used to trigger Qualys scans.

The batching rule is still:

> Put requests together only when one ODST/Qualys API request can represent all of them.

Example key:

```go
type ODSTBatchKey struct {
    Operation         string // e.g. "qualys-scan"
    ScanProfile       string
    ScannerTarget     string
    CompatibilityHash string
}
```

Possible conceptual key:

```text
qualys-scan|prod-standard|scanner-group-a|HASH
```

Example bucket:

```text
ODST bucket: qualys-scan/prod-standard

    vm001
    vm009
    vm037
    vm081

       |
       v
one ODST call
       |
       v
Qualys scan
```

If all ODST scan requests truly share identical configuration, there may be only one active internal bucket most of the time.

If profiles, scanner targets, endpoints, or policies vary, use multiple internal buckets.

---

# 14. DMS / BoKS batching

DMS calls BoKS APIs to remove host groups from servers.

Example:

```text
vm001 -> remove host group "unix-admin"
vm002 -> remove host group "unix-admin"
vm003 -> remove host group "db-admin"
vm004 -> remove host group "unix-admin"
```

If the BoKS/DMS request contains one common host group plus many servers:

```text
Bucket A:
  operation = remove-host-group
  hostGroup = unix-admin
  servers = vm001, vm002, vm004

Bucket B:
  operation = remove-host-group
  hostGroup = db-admin
  servers = vm003
```

Recommended key:

```go
type DMSBatchKey struct {
    Operation         string
    HostGroup         string
    CompatibilityHash string
}
```

Add endpoint, realm, tenant, domain, or any other common request parameter if the DMS/BoKS API requires it.

---

# 15. Three coordinator Workflow IDs

Use stable IDs:

```text
batch:ansible
batch:odst
batch:dms
```

These are infrastructure workflows.

They should normally remain running indefinitely through Continue-As-New chains.

The same Workflow ID is retained across Continue-As-New. A new Run ID is created.

Example:

```text
Workflow ID: batch:ansible

Run A
  |
  +-- Continue-As-New
          |
          v
Run B
  |
  +-- Continue-As-New
          |
          v
Run C
```

---

# 16. Coordinator startup

Because VM workflows use `SignalExternalWorkflow`, the coordinator must exist.

Recommended operational model:

```text
Service / deployment bootstrap
    |
    +--> ensure batch:ansible exists
    +--> ensure batch:odst exists
    +--> ensure batch:dms exists
```

Treat `WorkflowExecutionAlreadyStarted` as success when another bootstrap instance already created the workflow.

Do not terminate/recreate these workflows during ordinary application deployments.

Workers can restart independently from Workflow Executions.

For client-originated submissions, Temporal also provides `SignalWithStartWorkflow`. Inside another Workflow, normal `SignalExternalWorkflow` is the direct primitive, so stable prestarted coordinators keep the workflow-to-workflow path simple.

---

# 17. Request identity

Do not deduplicate only by caller Workflow ID.

One VM workflow may legitimately perform:

```text
scan
patch
privilege removal
post-patch scan
```

Therefore:

```text
RequestID != CallerWorkflowID
```

Recommended logical identity:

```text
RequestID =
    CallerWorkflowID
    +
    LogicalOperationInstanceID
```

Examples:

```text
vm:server123:scan:pre-patch
vm:server123:patch:monthly-2026-10
vm:server123:scan:post-patch
vm:server123:privilege-removal:phase-1
```

Do not use the caller Temporal Run ID as the primary identity. The caller may Continue-As-New, which changes Run ID while retaining the same logical Workflow ID.

---

# 18. Common request envelope

A shared envelope is useful:

```go
type BatchRequestEnvelope struct {
    RequestID string

    CallerWorkflowID string

    // Business/logical operation instance.
    LogicalOperationID string

    VM string

    SubmittedAt time.Time

    // Optional trace/correlation value.
    CorrelationID string
}
```

`SubmittedAt` must be populated deterministically. If constructed inside workflow code, use `workflow.Now(ctx)`.

Provider-specific request structures extend the common envelope.

Example:

```go
type AnsibleBatchRequest struct {
    Envelope BatchRequestEnvelope
    Target   ResolvedAnsibleTarget
}

type ODSTBatchRequest struct {
    Envelope BatchRequestEnvelope
    Target   ResolvedODSTTarget
}

type DMSBatchRequest struct {
    Envelope BatchRequestEnvelope
    Target   ResolvedDMSTarget
}
```

---

# 19. Signal names

Prefer stable signal names.

Example:

```text
submit
batch-result
```

Do not create a different Temporal signal name for every RequestID.

Use the RequestID inside the payload.

Example:

```go
type BatchResultSignal struct {
    RequestID string

    BatchExecutionID string

    Success bool

    ExternalExecutionID string

    ErrorCode    string
    ErrorMessage string
}
```

This keeps signal handling simple and observable.

---

# 20. Caller workflow lifecycle

Example VM workflow path:

```text
+---------------------------+
| VM Workflow               |
+-------------+-------------+
              |
              | needs PATCH
              v
+---------------------------+
| ResolveAnsibleTarget      |
| Activity                  |
+-------------+-------------+
              |
              | primary / job / 101
              v
+---------------------------+
| Create stable RequestID   |
+-------------+-------------+
              |
              | SignalExternalWorkflow
              v
+---------------------------+
| batch:ansible             |
+-------------+-------------+
              |
              | source workflow waits
              v
+---------------------------+
| wait for batch-result     |
| matching RequestID        |
+-------------+-------------+
              |
              v
     continue VM workflow
```

Waiting for the result does not occupy a worker thread.

Temporal persists workflow state and schedules another Workflow Task when a relevant event arrives.

---

# 21. Caller result handling

A VM workflow may have more than one outstanding operation over its lifetime.

A stable result signal is therefore preferable.

Example conceptual handler:

```go
resultCh := workflow.GetSignalChannel(ctx, "batch-result")

for {
    var result BatchResultSignal
    resultCh.Receive(ctx, &result)

    if result.RequestID != expectedRequestID {
        // Store or route the result rather than discarding it.
        // A real implementation should have a deterministic mailbox/map.
        continue
    }

    if !result.Success {
        return handleBatchFailure(result)
    }

    break
}
```

A more complete implementation can maintain a deterministic in-workflow mailbox for result signals so that a result for another operation is not lost.

Signals are durable and may arrive before the workflow reaches the receive point.

---

# 22. Coordinator internal state

Example:

```go
type CoordinatorState struct {
    Buckets map[string]BatchBucket

    // Requests currently waiting in buckets.
    PendingRequestIDs map[string]bool

    // Bounded recent dedup window.
    RecentRequestIDs map[string]RecentRequestRecord

    // Deterministic queue/list used to prune RecentRequestIDs.
    RecentRequestOrder []string
}
```

Bucket:

```go
type BatchBucket struct {
    Key string

    Requests []ProviderBatchRequest

    FirstRequestAt time.Time

    // Absolute deadline, not "remaining duration".
    FlushDeadline time.Time
}
```

Use maps for direct lookup.

**Important Temporal determinism rule:** do not rely on random Go map iteration order to decide workflow behavior.

Whenever bucket iteration influences decisions:

```text
map keys
   |
   v
copy keys to slice
   |
   v
sort.Strings(keys)
   |
   v
iterate sorted keys
```

---

# 23. Batch size and timeout

Example policy:

```go
type BatchPolicy struct {
    MaxBatchSize int
    MaxWait      time.Duration
}
```

Example:

```text
MaxBatchSize = 20
MaxWait      = 5 minutes
```

The five-minute window starts when the **first request enters an empty bucket**.

```text
t=00:00 VM01 arrives
        |
        +--> bucket created
        +--> deadline = 00:05

t=00:30 VM02 arrives
t=01:00 VM03 arrives

deadline remains 00:05
```

Do not reset the timer every time a request arrives.

Otherwise a continuously active low-volume bucket could wait indefinitely.

---

# 24. Flush rules

A bucket flushes when:

```text
size >= MaxBatchSize
```

OR:

```text
workflow.Now(ctx) >= FlushDeadline
```

If a bucket somehow contains more than the maximum size, flush deterministic chunks.

Example:

```text
47 requests
MaxBatchSize = 20

Batch A = first 20
Batch B = next 20
Batch C = remaining 7
```

Preserve deterministic ordering.

A useful ordering is acceptance order.

---

# 25. Timer implementation strategy

With one Ansible coordinator and many internal buckets, creating one Temporal timer per bucket is possible but can create more history and more timer-management complexity.

Recommended optimization:

> Maintain one active timer for the earliest bucket deadline.

State example:

```text
Bucket A deadline = 10:05
Bucket B deadline = 10:08
Bucket C deadline = 10:12
```

Only schedule:

```text
Timer -> 10:05
```

When it fires:

1. compute `workflow.Now(ctx)`;
2. flush every bucket whose deadline is now due;
3. compute the next earliest deadline;
4. create the next timer.

---

# 26. Coordinator event loop concept

```text
                 +-----------------------+
                 | Coordinator main loop |
                 +-----------+-----------+
                             |
                             v
                  Drain/process ready work
                             |
                             +--> flush full buckets
                             |
                             +--> flush expired buckets
                             |
                             v
                  Continue-As-New needed?
                             |
                +------------+-------------+
                |                          |
               no                         yes
                |                          |
                v                          v
     compute earliest deadline     safe rollover procedure
                |
                v
          create selector
                |
          +-----+------+
          |            |
          v            v
     submit signal   timer fires
          |            |
          +-----+------+
                |
                v
            loop again
```

---

# 27. Use Temporal workflow primitives only

Inside Workflow code use:

```go
workflow.GetSignalChannel(...)
workflow.NewSelector(...)
workflow.NewTimer(...)
workflow.Now(...)
workflow.Go(...)
workflow.NewContinueAsNewError(...)
```

Do not use:

```go
go func() {}
make(chan ...)
select {}
time.NewTimer(...)
time.After(...)
time.Sleep(...)
time.Now()
```

Native Go primitives are not replay-safe replacements for Temporal workflow primitives.

Activities use normal Go `context.Context` and normal libraries.

---

# 28. Recommended flushed-batch architecture

Do **not** let a long-running coordinator monitor a potentially long-running Ansible/Qualys/BoKS operation itself.

Use:

```text
Batch Coordinator
      |
      | bucket ready
      v
start BatchExecutionWorkflow
      |
      +----------------------------+
      |                            |
      | coordinator immediately   |
      | resumes batching           |
      |                            |
      v                            v
new requests                 Batch Execution
                                  |
                                  +--> launch
                                  +--> monitor once
                                  +--> collect results
                                  +--> signal VM workflows
```

This solves several problems:

- coordinator remains responsive;
- one downstream job is monitored only once;
- VM workflows do not all poll the same Ansible/Qualys job;
- Continue-As-New of the coordinator is easier;
- long downstream execution history is isolated to a finite execution workflow;
- retry and timeout policies can differ by integration.

---

# 29. BatchExecutionID

Every flushed batch receives a deterministic identity.

Recommended:

```text
BatchExecutionID =
    hash(
        provider
        +
        canonical BatchKey
        +
        sorted RequestIDs
    )
```

Example:

```text
ansible
primary|job-template|101|HASH-A
req-001
req-002
req-003
```

produces:

```text
BATCH-76F...
```

Sort RequestIDs before hashing so replay and input ordering cannot accidentally produce a different hash when the logical membership is identical.

Do not include:

- Activity attempt number;
- Temporal Run ID;
- current wall clock time;
- random UUID generated nondeterministically.

---

# 30. Batch Execution Workflow ID

Use the deterministic batch ID in the Workflow ID.

Example:

```text
batch-exec:ansible:BATCH-76F...
batch-exec:odst:BATCH-A91...
batch-exec:dms:BATCH-223...
```

This creates a strong Temporal-level deduplication boundary.

Recommended child options conceptually:

```go
workflow.ChildWorkflowOptions{
    WorkflowID: batchExecutionWorkflowID,

    ParentClosePolicy:
        enumspb.PARENT_CLOSE_POLICY_ABANDON,

    WorkflowIDReusePolicy:
        enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
}
```

Why `ABANDON`?

The long-running coordinator may Continue-As-New. Child workflows do not automatically move into the new parent run. An abandoned child is allowed to continue when the current coordinator run closes.

Why `REJECT_DUPLICATE`?

If coordinator logic attempts to start the exact same logical batch again, Temporal can reject reuse of the same completed Workflow ID during the applicable retention period.

This is a defense-in-depth layer, not a substitute for downstream API idempotency.

---

# 31. Important: wait until the child is actually started

When using an abandoned child workflow, do not start it and immediately Continue-As-New.

The parent must wait until the child start has been accepted.

Conceptual pattern:

```go
future := workflow.ExecuteChildWorkflow(
    childCtx,
    BatchExecutionWorkflow,
    input,
)

if err := future.GetChildWorkflowExecution().Get(ctx, nil); err != nil {
    return err
}

// Only now consider the batch handed off.
```

After the child start is recorded:

- remove those requests from the pending bucket;
- add request IDs to the bounded recent dedup state;
- allow the coordinator to Continue-As-New later.

---


# 32. Batch Execution Workflow responsibilities

The Batch Execution Workflow owns exactly one flushed batch and becomes the **single owner of the downstream execution ID** for that batch.

For asynchronous integrations such as Ansible and ODST/Qualys, the Batch Execution Workflow must poll the external operation **once per polling interval**, regardless of whether the batch contains 2, 10, or 100 VM requests.

```text
10 VM workflows
       |
       v
+----------------------+
| Batch Coordinator    |
| collects 10 requests |
+----------+-----------+
           |
           | flush
           v
+-------------------------------+
| BatchExecutionWorkflow B123   |
|                               |
| external Job ID = J456        |
|                               |
| THIS workflow polls J456      |
| exactly once per interval     |
+---------------+---------------+
                |
                v
             Ansible
                |
          Job J456 status
                |
                v
+-------------------------------+
| BatchExecutionWorkflow        |
| fans status to all callers    |
+--+--+--+--+--+--+--+--+--+---+
   |  |  |  |  |  |  |  |  |   
   v  v  v  v  v  v  v  v  v
  WF1 WF2 WF3 ...             WF10
```

The caller workflows must **not** each receive the Job ID and independently poll Ansible.

Bad:

```text
                  Job J456
                 /   |   \
                /    |    \
              WF1   WF2   ... WF10
               |     |         |
             poll  poll      poll
```

That creates duplicate external calls, duplicate retry logic, unnecessary Temporal history, and ten separate views of the same downstream execution.

Recommended:

```text
                    Job J456
                        ^
                        |
                     poll once
                        |
              BatchExecutionWorkflow
                /   /   |   \   \
               v   v    v    v   v
              WF1 WF2  WF3 ... WF10
                status signals
```

The Batch Execution Workflow should:

1. launch the downstream operation once;
2. retain the returned external execution ID;
3. poll the operation centrally;
4. convert provider status into a normalized status model;
5. optionally broadcast non-terminal progress after each poll;
6. immediately broadcast terminal status;
7. complete only after terminal status has been delivered, subject to the configured orphan-result policy.

The coordinator is no longer involved after the child Batch Execution Workflow has started.

---

# 33. Ansible Batch Execution and centralized polling

Input:

```go
type AnsibleBatchExecutionInput struct {
    BatchExecutionID string

    Target ResolvedAnsibleTarget

    Requests []AnsibleBatchRequest
}
```

Execution:

```text
BatchExecutionWorkflow
    |
    v
LaunchAnsibleBatchActivity
    |
    +--> Primary or Secondary Ansible
    |
    +--> Job Template API
    |        OR
    +--> Workflow Job Template API
    |
    v
Ansible Job / Workflow Job ID
    |
    | owned by this Batch Execution Workflow
    |
    v
+------------------------------------+
| CENTRAL DURABLE POLLING LOOP       |
|                                    |
| GetAnsibleStatusActivity(JobID)    |
|          |                         |
|          v                         |
| normalize state                    |
|          |                         |
|          v                         |
| fan status to callers              |
|          |                         |
|   terminal? ---- yes ---> finish   |
|          |                         |
|         no                         |
|          |                         |
|          v                         |
| Temporal durable timer             |
|          |                         |
|          +-----------> poll again  |
+------------------------------------+
```

Do not run one long HTTP-polling Activity that occupies a worker for the entire Ansible execution if the Ansible API supports status queries.

Prefer:

```text
short status Activity
      |
durable Temporal timer
      |
short status Activity
      |
durable Temporal timer
```

Benefits:

- exactly one logical Ansible poll per batch interval;
- worker restart friendly;
- no worker thread is held during the wait;
- all VMs observe one authoritative external status;
- retry scope is limited to one status call;
- cancellation and timeouts are easier to reason about;
- downstream API load is drastically lower than caller-side polling.

---

## 33.1 Normalized batch status

Use a provider-independent status envelope where practical.

```go
type BatchExecutionState string

const (
    BatchStatePending   BatchExecutionState = "PENDING"
    BatchStateRunning   BatchExecutionState = "RUNNING"
    BatchStateSuccess   BatchExecutionState = "SUCCESS"
    BatchStateFailed    BatchExecutionState = "FAILED"
    BatchStateCancelled BatchExecutionState = "CANCELLED"
)

type BatchStatusSignal struct {
    RequestID        string
    BatchExecutionID string

    Provider string

    ExternalExecutionID string

    State BatchExecutionState

    // Proves that the monitor actually contacted the provider.
    PollSequence int
    LastPolledAt time.Time

    Message string

    // Optional provider-specific status code/name for diagnostics.
    ProviderState string
}
```

Terminal-state determination should be explicit:

```go
func IsTerminal(state BatchExecutionState) bool {
    switch state {
    case BatchStateSuccess,
        BatchStateFailed,
        BatchStateCancelled:
        return true
    default:
        return false
    }
}
```

Add other terminal states if the actual Ansible/ODST/DMS APIs require them.

---

## 33.2 Poll once, signal many

Example for a batch containing ten VMs:

```text
Poll #1
   |
   v
Ansible => RUNNING
   |
   v
BatchExecutionWorkflow
   |
   +--> WF1 : RUNNING
   +--> WF2 : RUNNING
   +--> WF3 : RUNNING
   ...
   +--> WF10: RUNNING

Poll #2
   |
   v
Ansible => RUNNING
   |
   v
optional RUNNING heartbeat fan-out

Poll #3
   |
   v
Ansible => SUCCESS
   |
   v
BatchExecutionWorkflow
   |
   +--> WF1 : SUCCESS
   +--> WF2 : SUCCESS
   ...
   +--> WF10: SUCCESS
```

All ten workflows refer to one shared external Job ID, but none of them poll it.

---

## 33.3 Batch Execution polling skeleton

Architecture-oriented example:

```go
func AnsibleBatchExecutionWorkflow(
    ctx workflow.Context,
    input AnsibleBatchExecutionInput,
) error {
    logger := workflow.GetLogger(ctx)

    launchCtx := workflow.WithActivityOptions(
        ctx,
        launchActivityOptions(),
    )

    var launch AnsibleLaunchResult

    if err := workflow.ExecuteActivity(
        launchCtx,
        LaunchAnsibleBatchActivity,
        input,
    ).Get(ctx, &launch); err != nil {
        return signalLaunchFailureToAll(ctx, input, err)
    }

    logger.Info(
        "Ansible batch launched",
        "batchExecutionID", input.BatchExecutionID,
        "jobID", launch.ExternalExecutionID,
        "requestCount", len(input.Requests),
    )

    monitor := BatchMonitorState{
        ExternalExecutionID: launch.ExternalExecutionID,
        PollSequence:        0,
    }

    for {
        if err := workflow.Sleep(ctx, time.Minute); err != nil {
            return err
        }

        monitor.PollSequence++

        var providerStatus AnsibleJobStatus

        pollCtx := workflow.WithActivityOptions(
            ctx,
            statusActivityOptions(),
        )

        if err := workflow.ExecuteActivity(
            pollCtx,
            GetAnsibleJobStatusActivity,
            monitor.ExternalExecutionID,
        ).Get(ctx, &providerStatus); err != nil {
            return err
        }

        now := workflow.Now(ctx)

        normalized := normalizeAnsibleStatus(
            providerStatus,
            monitor.PollSequence,
            now,
        )

        if shouldNotifyCallers(monitor, normalized, now) {
            if err := signalBatchStatusToAll(
                ctx,
                input,
                monitor.ExternalExecutionID,
                normalized,
            ); err != nil {
                return err
            }

            monitor.LastNotifiedState = normalized.State
            monitor.LastNotifiedAt = now
        }

        if IsTerminal(normalized.State) {
            return nil
        }

        if workflow.GetInfo(ctx).GetContinueAsNewSuggested() {
            return continueMonitoringAsNew(
                ctx,
                input,
                monitor,
            )
        }
    }
}
```

The exact polling interval is provider/operation-specific and should be configurable.

---

## 33.4 Caller workflow behavior

The VM workflow waits on a stable status signal:

```text
submit request
      |
      v
wait for "batch-status"
      |
      v
status received
      |
      +--> PENDING/RUNNING
      |        |
      |        +--> log/update progress
      |        |
      |        +--> wait again
      |
      +--> SUCCESS
      |        |
      |        +--> resume normal workflow
      |
      +--> FAILED/CANCELLED
               |
               +--> resume failure handling
```

Example:

```go
func WaitForBatchCompletion(
    ctx workflow.Context,
    requestID string,
) error {
    logger := workflow.GetLogger(ctx)

    statusCh := workflow.GetSignalChannel(
        ctx,
        "batch-status",
    )

    for {
        var status BatchStatusSignal
        statusCh.Receive(ctx, &status)

        if status.RequestID != requestID {
            // Do not discard unmatched signals.
            // Store them in a deterministic mailbox keyed by RequestID.
            continue
        }

        logger.Info(
            "Batch operation status",
            "requestID", status.RequestID,
            "batchExecutionID", status.BatchExecutionID,
            "externalExecutionID", status.ExternalExecutionID,
            "state", status.State,
            "providerState", status.ProviderState,
            "pollSequence", status.PollSequence,
            "lastPolledAt", status.LastPolledAt,
        )

        switch status.State {
        case BatchStateSuccess:
            return nil

        case BatchStateFailed:
            return temporal.NewNonRetryableApplicationError(
                status.Message,
                "BATCH_OPERATION_FAILED",
                nil,
            )

        case BatchStateCancelled:
            return temporal.NewNonRetryableApplicationError(
                status.Message,
                "BATCH_OPERATION_CANCELLED",
                nil,
            )

        default:
            // PENDING / RUNNING:
            // log it and block again waiting for the next Signal.
        }
    }
}
```

When a non-terminal signal arrives, the VM Workflow does briefly run a Workflow Task, logs the progress message, and then blocks again. It does **not** occupy a worker thread while waiting for the next signal.

Use `workflow.GetLogger(ctx)` for Workflow logs.

---

## 33.5 Do not discard an unmatched status signal

A caller can potentially have multiple logical operations over its lifetime.

Do not simply:

```go
if status.RequestID != wanted {
    continue
}
```

and permanently lose the signal.

Maintain a deterministic mailbox:

```go
map[RequestID][]BatchStatusSignal
```

or route status through one centralized Workflow signal handler.

When map iteration can affect workflow decisions, sort keys before iteration.

---

## 33.6 Signal every poll vs throttled heartbeat

It is technically valid to fan a status signal to every caller after **every successful poll**.

For example:

```text
poll every 1 minute
batch size = 10
job duration = 60 minutes

60 polls
x 10 caller signals
= 600 progress signals
```

That may be desirable when the business explicitly requires proof of polling at every interval.

However, every signal adds Workflow History work to the receiving Workflow, and an external workflow signal also contributes signal-related history to the sender.

Recommended default:

```text
Poll provider:
    every 1 minute

Notify callers immediately:
    when state changes
    OR
    when terminal state is reached

While state is unchanged RUNNING:
    send a heartbeat every 5 minutes
```

Example:

```text
00:01 RUNNING -> signal
00:02 RUNNING -> no signal
00:03 RUNNING -> no signal
00:04 RUNNING -> no signal
00:05 RUNNING -> heartbeat signal
00:06 RUNNING -> no signal
...
00:09 SUCCESS -> signal immediately
```

This preserves visibility while reducing history.

If the requirement is literally "notify after every poll," keep that behavior configurable:

```go
type ProgressNotificationPolicy struct {
    NotifyEveryPoll bool

    // Used when NotifyEveryPoll == false.
    UnchangedHeartbeatInterval time.Duration
}
```

The terminal state must always be notified immediately.

---

## 33.7 Progress signal meaning

A progress signal should communicate both:

1. **external job state**; and
2. **monitor health/progress**.

Example log:

```text
Ansible Job 456 is RUNNING.
Poll #8 completed successfully at 14:35:00.
```

This is more useful than repeatedly saying only:

```text
RUNNING
```

Fields such as `LastPolledAt` and `PollSequence` let the caller and operations teams know that the monitoring workflow is actively making progress.

---

## 33.8 Per-host status vs batch-wide status

Ansible can expose a job-level status while individual hosts may have different final outcomes.

During execution:

```text
Job J456 = RUNNING
```

can be broadcast to every request.

At terminal completion, if host-level result data is available, map each VM independently:

```text
Job J456 = FAILED overall

VM01 -> SUCCESS
VM02 -> SUCCESS
VM03 -> FAILED
VM04 -> SUCCESS
...
```

Do not automatically fail all callers merely because the batch-level job status is failed when authoritative per-host results are available.

Final fan-out should prefer per-request truth.

---

## 33.9 Continue-As-New for a very long Batch Execution Workflow

Most Batch Execution Workflows should be finite and short enough that they do not need Continue-As-New.

However, an unusually long Ansible job or Qualys scan can accumulate history through:

```text
poll Activity
timer
poll Activity
timer
progress Signals
...
```

The Batch Execution Workflow may therefore also check:

```go
workflow.GetInfo(ctx).GetContinueAsNewSuggested()
```

If suggested, continue monitoring in a fresh Run.

Carry:

```go
type BatchMonitorState struct {
    ExternalExecutionID string

    PollSequence int

    LastObservedState BatchExecutionState

    LastNotifiedState BatchExecutionState
    LastNotifiedAt    time.Time
}
```

and the original batch input:

```text
BatchExecutionID
resolved target
caller/request list
```

The new run must continue polling the **same external Job ID**.

It must **not launch another Ansible/Qualys operation**.

```text
Run A

launch Job J456
poll
poll
poll
history growing
    |
    | Continue-As-New
    v

Run B

Job ID still J456
DO NOT LAUNCH AGAIN
    |
    +--> continue status polling
```

The Batch Execution Workflow ID remains in the same Continue-As-New chain.

---

# 34. ODST / Qualys Batch Execution

ODST follows the same centralized-monitoring rule as Ansible.

```text
10 VM requests
      |
      v
ODST BatchExecutionWorkflow
      |
      v
LaunchODSTScanActivity
      |
      v
ODST / Qualys Scan ID
      |
      v
ONE centralized polling loop
      |
      +--> PENDING/RUNNING progress signals
      |
      +--> terminal result signals
      v
caller workflows
```

Do not let every VM workflow poll the same Qualys scan.

For long scans, apply the same configurable progress-notification policy and Batch Execution Continue-As-New behavior.

---

# 35. DMS / BoKS Batch Execution

DMS/BoKS uses the same result contract, but polling depends on the downstream API behavior.

If the host-group removal call is synchronous:

```text
DMS BatchExecutionWorkflow
      |
      v
RemoveHostGroupsBatchActivity
      |
      v
DMS / BoKS
      |
      v
final result
      |
      v
signal callers
```

No polling loop is required.

If DMS/BoKS returns an asynchronous operation ID:

```text
launch once
    |
    v
external operation ID
    |
    v
centralized polling loop
    |
    +--> progress signals
    |
    +--> terminal result
```

The caller workflows still never poll the same external operation independently.

---

# 36. Full end-to-end example: Ansible patch

```text
VM01 Workflow
   |
   | PATCH / PROD / domainA
   v
ResolveAnsibleTargetActivity
   |
   | routing => PRIMARY
   | config => Job Template 101
   v
RequestID = vm01:patch:2026-10
   |
   | signal submit
   v
batch:ansible
   |
   | bucket:
   | primary|job|101|compat-A
   |
   +-- VM01
   +-- VM03
   +-- VM05
   +-- ...
   +-- VM20
   |
   | size == 20
   v
compute BatchExecutionID
   |
   v
start child:
batch-exec:ansible:<id>
   |
   | wait until child STARTED
   |
   +-------------------------------> coordinator returns to batching
                                      |
                                      +--> VM21...
                                      +--> VM22...
                                      +--> next batch
```

Execution:

```text
batch-exec:ansible:<id>
    |
    v
LaunchAnsibleBatchActivity
    |
    v
POST Primary Ansible
/job_templates/101/launch
    |
    | VMs = [VM01, VM03, VM05, ... VM20]
    v
Job ID 456789
    |
    v
Monitor once
    |
    v
terminal result
    |
    +--> signal VM01 RequestID result
    +--> signal VM03 RequestID result
    +--> signal VM05 RequestID result
    ...
```

---

# 37. Request deduplication

There are several different duplicate problems. They must not be collapsed into one mechanism.

## 37.1 Duplicate logical submission

Example:

```text
same VM workflow
same logical patch step
signal submitted twice
```

Use `RequestID`.

Coordinator state:

```go
PendingRequestIDs map[string]bool
RecentRequestIDs  map[string]RecentRequestRecord
```

On signal:

```text
RequestID already Pending?
       |
      yes -> ignore
       |
      no
       v
RequestID in recent dedup window?
       |
      yes -> ignore or resend known acknowledgement/result
       |
      no
       v
accept
```

---

# 38. Why Workflow ID alone is insufficient

Bad:

```text
RequestID = CallerWorkflowID
```

because one workflow may submit:

```text
scan
patch
privilege-removal
scan again
```

Better:

```text
RequestID = CallerWorkflowID + LogicalOperationInstanceID
```

The logical operation instance must distinguish intentionally repeated operations.

---

# 39. Recent dedup state must be bounded

Never accumulate every RequestID forever inside a permanent coordinator.

Possible policy:

```text
retain last N RequestIDs
```

or:

```text
retain IDs for a deterministic business window
```

For Workflow determinism, time comparisons use `workflow.Now(ctx)`.

Use a deterministic ordered list for pruning.

Example:

```go
type RecentRequestRecord struct {
    CompletedAt time.Time
}

type CoordinatorState struct {
    RecentRequestIDs   map[string]RecentRequestRecord
    RecentRequestOrder []string
}
```

Do not use a nondeterministic cache implementation inside Workflow code.

---

# 40. Strong dedup beyond the coordinator

A bounded recent set is not permanent deduplication.

If duplicate prevention must survive arbitrarily long periods, use a durable external idempotency ledger in the Activity/integration layer.

Example logical table:

```text
request_id
batch_execution_id
provider
external_execution_id
status
created_at
updated_at
```

However, external persistent state introduces its own consistency design and should only be added if the business requirement needs long-lived deduplication.

---

# 41. Batch-level deduplication

Batch-level identity is separate from request identity.

Example:

```text
Batch B1:
  Request A
  Request B
  Request C
```

`BatchExecutionID` identifies the external multi-server operation.

It is used for:

- Batch Execution Workflow ID;
- downstream idempotency/correlation key;
- logs;
- tracing;
- metrics;
- result correlation.

---

# 42. Activity execution is not exactly-once side-effect execution

Important failure case:

```text
Activity attempt 1
    |
    v
POST Ansible launch
    |
    v
Ansible accepts request
    |
    X Worker crashes before Temporal records Activity completion
```

Temporal may execute another Activity attempt.

```text
Activity attempt 2
    |
    v
POST again
```

Without downstream idempotency this may create a duplicate external job.

Therefore:

> Every side-effecting external launch should use the same deterministic `BatchExecutionID` on every Activity attempt.

---

# 43. Downstream idempotency strategy

Best case:

```text
downstream API supports idempotency key
```

Send:

```text
Idempotency-Key: <BatchExecutionID>
```

or the provider's equivalent.

If no native idempotency field exists, use the most reliable correlation mechanism offered by the system.

Possible strategies:

1. Native idempotency key.
2. Client request ID accepted by the API.
3. Correlation ID embedded in launch metadata/extra-vars/tags plus lookup-before-relaunch.
4. Durable integration ledger.
5. At minimum, search for an already-created execution by deterministic correlation before launching again.

If a downstream system provides no idempotency key, no searchable correlation field, and no transactional way to couple its launch with your ledger, **true exactly-once external side effects cannot be guaranteed** across the crash-after-accept ambiguity.

The design should explicitly document that limitation.

---

# 44. Activity retries

Configure retries according to provider behavior.

Example:

```go
workflow.ActivityOptions{
    StartToCloseTimeout: 30 * time.Second,
    RetryPolicy: &temporal.RetryPolicy{
        InitialInterval:    time.Second,
        BackoffCoefficient: 2,
        MaximumInterval:    30 * time.Second,
        MaximumAttempts:    5,
    },
}
```

Do not blindly retry:

- malformed requests;
- authorization failures that are not transient;
- invalid template IDs;
- unsupported host group names;
- validation failures.

Classify such failures as non-retryable application errors.

Retry likely transient conditions:

- transport interruption;
- gateway timeout;
- temporary 5xx response;
- service unavailable;
- rate limiting, when appropriate.

---


# 45. Polling activities

Polling belongs to the **Batch Execution Workflow**, not the individual VM workflows.

For every asynchronous downstream execution:

```text
Batch Execution Workflow
      |
      v
status Activity
      |
      v
normalize status
      |
      v
notify callers when policy says to
      |
      v
terminal?
   +--+--+
   |     |
  yes    no
   |     |
   v     v
finish  Temporal timer
             |
             v
        status Activity
```

Example:

```go
for {
    var status ProviderStatus

    err := workflow.ExecuteActivity(
        pollCtx,
        GetProviderStatusActivity,
        externalExecutionID,
    ).Get(ctx, &status)

    if err != nil {
        return err
    }

    normalized := normalizeProviderStatus(status)

    if shouldNotifyCallers(...) {
        if err := signalStatusToAll(...); err != nil {
            return err
        }
    }

    if normalized.Terminal {
        break
    }

    if err := workflow.Sleep(ctx, pollInterval); err != nil {
        return err
    }
}
```

A batch with ten VM requests still produces **one provider status call per poll interval**, not ten.

Use provider-specific Activity retry policy for transient polling failures.

`workflow.Sleep` and `workflow.NewTimer` are durable Workflow timing primitives.

---

# 46. Progress and final result fan-out

The Batch Execution Workflow signals each originating Workflow ID.

Use one stable signal name:

```text
batch-status
```

and put correlation inside the payload.

```text
BatchExecutionWorkflow
       |
       | poll => RUNNING
       |
       +--> Caller A / Request A : RUNNING
       +--> Caller B / Request B : RUNNING
       +--> Caller C / Request C : RUNNING
       |
       | later poll => SUCCESS
       |
       +--> Caller A / Request A : SUCCESS
       +--> Caller B / Request B : SUCCESS
       +--> Caller C / Request C : SUCCESS
```

Use the stable caller Workflow ID and normally leave Run ID empty so Temporal targets the currently running execution for that Workflow ID.

Conceptually:

```go
err := workflow.SignalExternalWorkflow(
    ctx,
    callerWorkflowID,
    "",
    "batch-status",
    status,
).Get(ctx, nil)
```

This is particularly important if the caller itself has Continued-As-New.

---

## 46.1 Caller semantics

Non-terminal:

```text
PENDING / RUNNING
      |
      v
log progress
      |
      v
wait for next batch-status Signal
```

Terminal:

```text
SUCCESS
   |
   v
continue next business step
```

or:

```text
FAILED / CANCELLED
   |
   v
execute caller failure path
```

The caller does not perform an Ansible/ODST/DMS status API call.

---

## 46.2 Notification policy

Supported:

```text
notify every poll
```

Recommended default:

```text
notify on state change
+
periodic unchanged-state heartbeat
+
always notify terminal state immediately
```

Reason:

- preserves operational visibility;
- provides proof that centralized monitoring is active;
- substantially reduces Event History growth for both Batch Execution and caller workflows.

---

## 46.3 Signal delivery failures

Do not rerun the external operation merely because one caller signal could not be delivered.

Each caller result is a fan-out/delivery concern, not a reason to relaunch the batch.

Apply the orphan/result-delivery policy described below.

---

# 47. If the caller no longer exists

Possible case:

```text
batch finishes
    |
    v
caller workflow already completed / terminated
```

The signal can fail.

Define policy explicitly.

Recommended:

- retry signal failures that are transient;
- treat "workflow not found / no active execution" as an orphan-result condition;
- log and metric the orphan;
- optionally persist final result externally if audit requirements require it.

Do not cause a whole 20-host batch to be retried because one source workflow disappeared.

---

# 48. Continue-As-New purpose

Permanent coordinators generate history from:

- incoming Signals;
- timers;
- child workflow starts;
- child start acknowledgements;
- cancellations;
- commands;
- other workflow events.

History must not grow indefinitely.

Temporal recommends keeping histories comfortably below hard limits; large histories increase replay cost.

The coordinators should use:

```go
workflow.GetInfo(ctx).GetContinueAsNewSuggested()
```

as the primary indication that rollover is appropriate.

---

# 49. Continue-As-New chain

```text
Workflow ID: batch:ansible

+-----------------------+
| Run A                 |
| history grows         |
+-----------+-----------+
            |
            | Continue-As-New
            v
+-----------------------+
| Run B                 |
| fresh history         |
+-----------+-----------+
            |
            | Continue-As-New
            v
+-----------------------+
| Run C                 |
+-----------------------+
```

Workflow ID stays the same.

Run ID changes.

---

# 50. Preferred Continue-As-New point: idle

Preferred condition:

```text
ContinueAsNewSuggested
AND
no pending bucket requests
AND
no child-start handoff currently in progress
```

Then:

```text
drain signal channel
      |
      +--> signal found?
      |       |
      |      yes
      |       |
      |       v
      |   process it and continue loop
      |
      +--> no signal
              |
              v
        Continue-As-New immediately
```

This is the cleanest rollover.

---

# 51. Why signal draining is required in Go

Before closing the current run through Continue-As-New, drain buffered Signals using `ReceiveAsync`.

Conceptual pattern:

```go
for {
    var req AnsibleBatchRequest

    if !signalCh.ReceiveAsync(&req) {
        break
    }

    acceptRequest(&state, req)
}
```

Important rule:

> After the final unsuccessful `ReceiveAsync`, do not block on another external event before issuing Continue-As-New.

If you yield again, more signals can become available and your previous drain is no longer the final close-time drain.

---

# 52. Non-idle Continue-As-New fallback

A coordinator under constant load may never become idle.

History safety must take priority over waiting forever for an idle moment.

Therefore support a state-carrying rollover.

Snapshot:

```go
type CoordinatorContinueState struct {
    Buckets []SerializableBucketState

    RecentRequestRecords []SerializableRecentRequest
}
```

For every pending bucket carry:

- canonical key;
- requests;
- `FirstRequestAt`;
- **absolute `FlushDeadline`**.

---

# 53. Do not reset batch deadlines after Continue-As-New

Bad:

```text
Original request waits 4 minutes
Continue-As-New
new 5-minute timer starts
total wait = 9 minutes
```

Correct:

```text
First request:       10:00
Original deadline:   10:05
Continue-As-New:     10:04

new run receives:
FlushDeadline = 10:05

remaining wait = 1 minute
```

On new run:

```go
remaining := bucket.FlushDeadline.Sub(workflow.Now(ctx))

if remaining <= 0 {
    flushImmediately()
}
```

---

# 54. Continue-As-New with detached Batch Execution Workflows

This is one reason the recommended design uses separate Batch Execution Workflows.

Once the coordinator has confirmed that the child workflow started with:

```text
ParentClosePolicy = ABANDON
```

the coordinator does not need to retain its execution state.

It can Continue-As-New while that execution continues independently.

The child will signal source VM workflows directly.

```text
Coordinator Run A
    |
    +--> BatchExecution X ---- continues
    |
    +--> Continue-As-New
             |
             v
       Coordinator Run B

BatchExecution X
    |
    +--> finishes later
    |
    +--> signals VM workflows
```

---

# 55. App/worker restart behavior

Suppose:

```text
batch:ansible

Bucket 101:
  VM1
  VM2
  VM3

deadline = 10:05

Worker process crashes at 10:03
```

The coordinator state is logically reconstructible from Temporal Event History.

```text
Worker crash
    |
    v
Temporal retains Workflow Execution + history
    |
    v
worker becomes available
    |
    v
Workflow Task scheduled
    |
    v
Workflow code replayed
    |
    v
signals/timers/activity results from history rebuild state
    |
    v
coordinator continues
```

No custom "reload batch queue from local memory" mechanism is required.

---

# 56. What replay actually means

Do not think of Temporal as restoring a Go heap snapshot.

Conceptually:

```text
start Workflow code from beginning
      |
      v
replay historical events
      |
      v
same decisions reproduced
      |
      v
current logical state reconstructed
```

Therefore deterministic workflow code is essential.

Activities that already completed are not re-executed simply because workflow code is replaying; their recorded results are supplied from history.

An incomplete Activity attempt may be retried according to Activity semantics and retry policy.

---

# 57. Restart during Batch Execution

Example:

```text
Launch Activity
   |
   v
external Ansible job created
   |
   X worker dies
```

After restart:

- Temporal knows whether the Activity completion was recorded.
- If not recorded, an Activity attempt may execute again.
- `BatchExecutionID` must therefore be reused as the external idempotency/correlation value.

If launch completed and its result was recorded:

```text
Job ID = 1234
```

the Batch Execution Workflow replay receives that recorded result and proceeds to monitoring.

---

# 58. Temporal Service restart

With a properly configured Temporal deployment using persistent storage, Workflow Event History and task state survive Temporal process restarts according to the Temporal service's durability model.

Do not compare this to running an ephemeral local development server with disposable storage.

Production durability depends on a correctly deployed Temporal cluster and persistence backend.

---

# 59. Coordinator state should stay small

Do not place large payloads in Signals or Workflow state.

Prefer:

```text
request IDs
VM identifiers
resolved small configuration references
small common parameters
```

Avoid:

```text
large reports
raw scan results
large API responses
binary content
huge inventories
```

Large results belong in external storage with references carried through Temporal.

---

# 60. History minimization strategy

Use several layers:

1. **Continue-As-New** when suggested.
2. Use **three integration coordinators**, not one system-wide coordinator.
3. Hand off flushed batches to separate finite execution workflows.
4. Keep workflow payloads small.
5. Use one earliest-deadline timer per coordinator when practical.
6. Avoid unnecessary signal chatter.
7. Avoid polling external systems from every VM workflow.
8. Bound request dedup state.
9. Avoid storing completed batch history in coordinator state.
10. Move large audit/report data outside workflow payloads.

---

# 61. Single coordinator throughput caveat

`batch:ansible` is one logical Workflow Execution at a time.

That means all Ansible submit signals are serialized through its Workflow Tasks.

For normal infrastructure orchestration volumes this can be desirable and simple.

If throughput eventually becomes too high, shard without changing the overall design.

Example:

```text
batch:ansible:0
batch:ansible:1
batch:ansible:2
batch:ansible:3
```

Choose shard deterministically from the BatchKey.

Do not prematurely shard.

Start with one coordinator, measure:

- submit signal rate;
- Workflow Task latency;
- schedule-to-start latency;
- history growth rate;
- number of active buckets.

---

# 62. Backpressure

Define limits.

Possible coordinator settings:

```text
MaxBatchSize
MaxWait
MaxPendingRequests
MaxBuckets
```

If the system receives more requests than it can launch safely, decide explicitly whether to:

- keep accepting;
- reject with a result signal;
- defer;
- apply integration-specific concurrency limits.

The Batch Execution layer may also need:

```text
MaxConcurrentAnsibleBatches
MaxConcurrentODSTScans
MaxConcurrentDMSBatches
```

Do not overload a downstream API merely because Temporal can schedule more work.

---

# 63. Integration concurrency

Batching and concurrency are different controls.

Example:

```text
Batch size = 20 VMs
Max concurrent Ansible executions = 5
```

Maximum potential active VMs:

```text
5 * 20 = 100
```

Use provider-side limits or a Temporal-aware concurrency mechanism appropriate for your deployment.

If concurrency gating becomes significant, consider a dedicated integration scheduler workflow or worker/task-queue rate controls rather than embedding nondeterministic semaphores.

---

# 64. Configuration change behavior

Suppose Job Template configuration changes while a bucket contains requests.

Recommended rule:

> A request keeps the resolved target it had when it was submitted.

New requests use the new configuration.

If the compatibility fingerprint changes, they naturally enter a different bucket.

Example:

```text
Old requests:
  Template 101
  CompatHash A

New config:
  Template 101
  CompatHash B

Result:
  old bucket = 101/A
  new bucket = 101/B
```

This prevents mixing requests that were resolved under incompatible configuration versions.

---

# 65. Configuration revision

Include a configuration revision or fingerprint in resolution outputs.

Example:

```text
config revision:
ansible-routing-2026-10-21.3
```

or a canonical content hash.

Use it for:

- logs;
- debugging;
- audit;
- compatibility decisions where appropriate.

Do not automatically include a revision in the BatchKey if two revisions are semantically identical for the relevant launch. Prefer the compatibility fingerprint of actual common execution parameters.

---

# 66. Secrets

Never persist sensitive credentials in Workflow history.

Workflow history can contain:

- Workflow inputs;
- Activity inputs/results;
- Signals;
- child Workflow inputs;
- failure details.

Activities should resolve secrets at execution time from the approved secret store/environment.

Prefer passing:

```text
AnsibleTarget = primary
```

rather than:

```text
AnsiblePassword = ...
```

---

# 67. Error model

Separate errors into categories.

## 67.1 Resolution errors

Examples:

- domain missing from routing config;
- no template for operation/domain;
- unsupported VM environment;
- invalid config.

These normally fail the logical request before it reaches batching.

---

## 67.2 Batch coordinator errors

Examples:

- invalid request envelope;
- invalid BatchKey;
- child execution could not be started.

Coordinator must not silently drop the request.

---

## 67.3 External launch errors

Examples:

- Ansible unavailable;
- ODST timeout;
- DMS gateway failure.

Use Activity retry policy.

After retries exhaust, Batch Execution Workflow signals failure to each affected request.

---

## 67.4 Provider accepted operation but monitoring fails

Do not relaunch immediately.

The external execution may already exist.

Continue monitoring using the known external execution ID.

---

## 67.5 Per-host partial failures

Example:

```text
Batch of 20

18 success
2 failed
```

Return individual results.

Do not mark all 20 as failed unless the provider exposes only a batch-wide failure with no per-host distinction.

---

# 68. Failure matrix

| Failure | Expected behavior |
|---|---|
| VM Workflow worker dies before submitting | VM workflow replay resumes and signal command is reconstructed |
| Coordinator worker dies with pending bucket | Replay reconstructs accepted signals and deadlines |
| Coordinator worker dies while starting execution child | Temporal history determines whether child start occurred |
| Execution worker dies before external launch | Activity retries |
| External launch succeeds, worker dies before Activity completion | Retry may happen; external idempotency key is required |
| Worker dies during polling wait | Durable timer/history resumes |
| External service unavailable | Activity retry/backoff |
| One VM fails in batch | Signal per-VM failure; do not fail unrelated successful VM requests |
| Caller workflow disappears | Record orphan signal/result; do not rerun whole batch |
| Coordinator history becomes large | Drain signals and Continue-As-New |
| Config changes | New requests resolve to new target/fingerprint |
| Duplicate submit signal | RequestID dedup |
| Duplicate batch start | deterministic BatchExecutionID + Workflow ID reuse policy |
| Duplicate external launch attempt | downstream idempotency/correlation |

---

# 69. Cancellation

Decide what cancellation means at each layer.

## Caller VM workflow cancelled before bucket flush

Possible desired behavior:

- leave request in batch and ignore eventual result; or
- send a cancellation/removal signal to coordinator.

Removing queued requests reduces unnecessary downstream work but adds coordination complexity.

Start simple unless cancellation volume matters.

---

## Caller VM workflow cancelled after batch launch

The VM is already part of a shared downstream operation.

Do not cancel the entire batch because one caller disappears.

The Batch Execution Workflow continues for the remaining participants.

---

## Batch Execution Workflow cancelled

Only allow this through explicit operational controls.

Be careful: cancelling Temporal state does not necessarily cancel an already-launched external job.

If provider cancellation is supported, implement it explicitly.

---

# 70. Observability

Every log/trace/metric should include relevant identifiers.

Recommended fields:

```text
provider
coordinatorWorkflowID
coordinatorRunID
requestID
callerWorkflowID
batchKey
batchExecutionID
externalExecutionID
operation
ansibleEnvironment
templateType
templateID
configRevision
vmCount
```

Do not log secrets.

---

# 71. Metrics

Useful metrics:

```text
batch_requests_received_total
batch_requests_deduplicated_total
batch_flush_total
batch_flush_size
batch_wait_seconds
batch_bucket_count
batch_pending_request_count
batch_execution_started_total
batch_execution_failed_total
batch_execution_duration_seconds
batch_result_signal_failed_total
batch_orphan_result_total
batch_continue_as_new_total
```

Provider-specific:

```text
ansible_batch_size
odst_scan_batch_size
dms_batch_size
ansible_job_duration
qualys_scan_duration
boks_operation_duration
```

---

# 72. Search attributes / visibility

Useful coordinator Search Attributes may include:

```text
Integration = ansible
Role        = batch-coordinator
```

Execution workflows may include:

```text
Integration       = ansible
BatchExecutionID  = ...
Operation         = patch
TemplateID        = ...
```

Only use Search Attributes for data that is useful for visibility/search.

Do not put unbounded or sensitive values into indexed fields.

---

# 73. Task queue design

A reasonable initial layout:

```text
workflow-orchestration
    - VM workflows
    - coordinators
    - batch execution workflows

ansible-activities
    - resolve/launch/status Ansible Activities

odst-activities
    - ODST/Qualys Activities

dms-activities
    - DMS/BoKS Activities
```

Or use one worker process with multiple task queues if operationally simpler.

Separate task queues become useful when:

- provider integrations require different credentials;
- concurrency limits differ;
- scaling differs;
- one provider must not starve another.

---

# 74. Worker deployments

Workers are stateless executors from the Workflow durability perspective.

You can run multiple replicas polling the same Task Queue.

```text
               Temporal Task Queue
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Worker 1    Worker 2    Worker 3
```

A Workflow Execution is not permanently tied to one worker process.

After failure or eviction, another worker can replay the history and continue.

---

# 75. Deployment/versioning caution

Workflow code must remain replay-compatible with histories created by earlier deployed versions.

When changing coordinator decision logic:

- use Temporal-supported workflow versioning/deployment practices;
- run replay tests against representative production histories;
- avoid changing deterministic ordering or branching in an incompatible way.

Activity implementation can usually evolve more freely because Activities are not replayed as Workflow code.

---

# 76. Deterministic coding checklist

Inside Workflow code:

- [ ] use `workflow.Now`, not `time.Now`;
- [ ] use `workflow.NewTimer`/`workflow.Sleep`, not native timers;
- [ ] use Temporal channels, not native channels;
- [ ] use `workflow.Go`, not native goroutines;
- [ ] use `workflow.Selector`, not native `select`;
- [ ] do not call HTTP/database/filesystem APIs;
- [ ] do not read mutable environment configuration directly;
- [ ] sort map keys before behavior-affecting iteration;
- [ ] use deterministic batch IDs;
- [ ] do not generate random UUIDs using ordinary random functions;
- [ ] keep payloads small.

---

# 77. Coordinator pseudo-code

The following is architectural pseudo-code, not a drop-in final implementation.

```go
func AnsibleBatchCoordinatorWorkflow(
    ctx workflow.Context,
    initial *AnsibleCoordinatorState,
) error {
    state := initializeState(initial)

    signalCh := workflow.GetSignalChannel(ctx, "submit")

    for {
        // 1. Process anything already due/full.
        if err := flushFullBuckets(ctx, &state); err != nil {
            return err
        }

        if err := flushExpiredBuckets(ctx, &state); err != nil {
            return err
        }

        // 2. History management.
        if workflow.GetInfo(ctx).GetContinueAsNewSuggested() {
            shouldContinue, err := prepareContinueAsNew(
                ctx,
                signalCh,
                &state,
            )
            if err != nil {
                return err
            }

            if shouldContinue {
                snapshot := buildContinueState(state)

                return workflow.NewContinueAsNewError(
                    ctx,
                    AnsibleBatchCoordinatorWorkflow,
                    snapshot,
                )
            }
        }

        // 3. Compute the next bucket deadline.
        nextDeadline, hasDeadline := earliestDeadline(state)

        selector := workflow.NewSelector(ctx)

        signalReceived := false

        selector.AddReceive(signalCh, func(
            c workflow.ReceiveChannel,
            more bool,
        ) {
            var req AnsibleBatchRequest
            c.Receive(ctx, &req)

            acceptAnsibleRequest(ctx, &state, req)
            signalReceived = true
        })

        if hasDeadline {
            delay := nextDeadline.Sub(workflow.Now(ctx))

            if delay <= 0 {
                continue
            }

            timer := workflow.NewTimer(ctx, delay)

            selector.AddFuture(timer, func(workflow.Future) {
                // Loop will flush all expired buckets.
            })
        }

        selector.Select(ctx)

        _ = signalReceived
    }
}
```

A production implementation should carefully manage timer cancellation if the earliest deadline changes before an existing timer fires.

---

# 78. Accepting an Ansible request

Conceptual:

```go
func acceptAnsibleRequest(
    ctx workflow.Context,
    state *AnsibleCoordinatorState,
    req AnsibleBatchRequest,
) {
    id := req.Envelope.RequestID

    if state.PendingRequestIDs[id] {
        return
    }

    if _, ok := state.RecentRequestIDs[id]; ok {
        return
    }

    key := buildCanonicalAnsibleBatchKey(req.Target)

    bucket, exists := state.Buckets[key]

    if !exists {
        now := workflow.Now(ctx)

        bucket = AnsibleBatchBucket{
            Key:            key,
            FirstRequestAt: now,
            FlushDeadline:  now.Add(state.Policy.MaxWait),
        }
    }

    bucket.Requests = append(bucket.Requests, req)

    state.Buckets[key] = bucket
    state.PendingRequestIDs[id] = true
}
```

---

# 79. Deterministic bucket iteration

Do not:

```go
for key, bucket := range state.Buckets {
    if bucketShouldFlush(bucket) {
        ...
    }
}
```

if iteration order can affect emitted Temporal commands.

Use:

```go
keys := make([]string, 0, len(state.Buckets))

for key := range state.Buckets {
    keys = append(keys, key)
}

sort.Strings(keys)

for _, key := range keys {
    bucket := state.Buckets[key]
    ...
}
```

This is especially important if multiple buckets become due in the same Workflow Task.

---

# 80. Flushing a bucket

Recommended handoff order:

```text
select requests
      |
      v
compute BatchExecutionID
      |
      v
build child input
      |
      v
start BatchExecutionWorkflow
      |
      v
WAIT UNTIL CHILD START CONFIRMED
      |
      v
remove requests from pending bucket
      |
      v
add RequestIDs to recent dedup state
      |
      v
continue batching
```

Do not remove pending requests before child start is durably confirmed.

---

# 81. Child start skeleton

```go
func startAnsibleBatchExecution(
    ctx workflow.Context,
    batch AnsibleBatchExecutionInput,
) error {
    childID :=
        "batch-exec:ansible:" + batch.BatchExecutionID

    opts := workflow.ChildWorkflowOptions{
        WorkflowID: childID,

        ParentClosePolicy:
            enumspb.PARENT_CLOSE_POLICY_ABANDON,

        WorkflowIDReusePolicy:
            enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
    }

    childCtx := workflow.WithChildOptions(ctx, opts)

    future := workflow.ExecuteChildWorkflow(
        childCtx,
        AnsibleBatchExecutionWorkflow,
        batch,
    )

    // Confirm the child is actually started.
    return future.GetChildWorkflowExecution().Get(ctx, nil)
}
```

Production code must decide how to handle an already-started error if the deterministic batch ID has already been launched.

---

# 82. Batch Execution Workflow skeleton

```go
func AnsibleBatchExecutionWorkflow(
    ctx workflow.Context,
    input AnsibleBatchExecutionInput,
) error {
    launchCtx := workflow.WithActivityOptions(
        ctx,
        workflow.ActivityOptions{
            StartToCloseTimeout: 30 * time.Second,
            RetryPolicy: &temporal.RetryPolicy{
                InitialInterval:    time.Second,
                BackoffCoefficient: 2,
                MaximumInterval:    30 * time.Second,
                MaximumAttempts:    5,
            },
        },
    )

    var launch AnsibleLaunchResult

    err := workflow.ExecuteActivity(
        launchCtx,
        LaunchAnsibleBatchActivity,
        input,
    ).Get(ctx, &launch)

    if err != nil {
        return signalBatchFailureToCallers(
            ctx,
            input,
            err,
        )
    }

    final, err := monitorAnsibleExecution(
        ctx,
        input,
        launch.ExternalExecutionID,
    )

    if err != nil {
        return signalBatchFailureToCallers(
            ctx,
            input,
            err,
        )
    }

    return signalResultsToCallers(
        ctx,
        input,
        final,
    )
}
```

The implementation can return successfully after failure result signals have been delivered, depending on whether business failure should count as Workflow failure.

Often it is useful to distinguish:

```text
integration execution completed with business failures
```

from:

```text
workflow infrastructure failed unexpectedly
```

---

# 83. Provider Activity structure

```text
Activities
|
+-- ResolveAnsibleTarget
|
+-- LaunchAnsibleBatch
|
+-- GetAnsibleExecutionStatus
|
+-- LaunchODSTBatch
|
+-- GetODSTScanStatus
|
+-- ExecuteDMSBatch
|
+-- GetDMSStatus              (only if async)
```

Keep external protocol knowledge in Activities.

Workflow code should orchestrate state transitions, retries, waiting, and messaging.

---

# 84. External launch input

Include:

```text
BatchExecutionID
Resolved target
List of VM requests
```

Do not include the Activity attempt number in the external request identity.

All Activity attempts for the same batch must reuse the same idempotency/correlation key.

---

# 85. Result model

```go
type BatchItemResult struct {
    RequestID string
    VM        string

    Success bool

    ExternalExecutionID string

    ErrorCode    string
    ErrorMessage string
}

type BatchExecutionResult struct {
    BatchExecutionID string

    Items []BatchItemResult
}
```

Preserve one result per logical request whenever downstream data allows it.

---

# 86. Continue-As-New pseudo-code

Preferred idle rollover:

```go
func tryIdleContinueAsNew(
    ctx workflow.Context,
    signalCh workflow.ReceiveChannel,
    state *CoordinatorState,
) bool {
    if !workflow.GetInfo(ctx).GetContinueAsNewSuggested() {
        return false
    }

    if len(state.Buckets) != 0 {
        return false
    }

    // Final non-blocking drain.
    drainedAny := false

    for {
        var req BatchRequest

        if !signalCh.ReceiveAsync(&req) {
            break
        }

        drainedAny = true
        acceptRequest(ctx, state, req)
    }

    // New work arrived, so do not close.
    if drainedAny {
        return false
    }

    // Return true and immediately issue Continue-As-New.
    // Do not block/yield between here and the Continue-As-New command.
    return true
}
```

---

# 87. State-carrying Continue-As-New pseudo-code

For a continuously busy coordinator:

```text
ContinueAsNewSuggested
       |
       v
finish any child-start handoff currently in progress
       |
       v
drain signal channel using ReceiveAsync
       |
       v
accept drained requests into buckets
       |
       v
snapshot:
  buckets
  request IDs
  absolute deadlines
  bounded recent dedup state
       |
       v
Continue-As-New immediately
```

Do not wait for detached Batch Execution Workflows.

They are already independent.

---

# 88. Serialize Continue-As-New state carefully

Prefer explicit structs over arbitrary interface maps.

Example:

```go
type AnsibleCoordinatorContinueState struct {
    Buckets []AnsibleBucketSnapshot

    RecentRequests []RecentRequestSnapshot
}

type AnsibleBucketSnapshot struct {
    Key string

    Requests []AnsibleBatchRequest

    FirstRequestAt time.Time
    FlushDeadline  time.Time
}
```

Sort buckets by key before snapshot generation.

This gives stable, debuggable inputs.

---

# 89. Coordinator idle definition

For this design, "idle" means:

```text
no queued requests in buckets
AND
no child start acknowledgement currently being awaited
```

It does **not** mean:

```text
no Batch Execution Workflow exists anywhere
```

Detached Batch Execution Workflows may still be running.

That is intentional.

---

# 90. Why execution workflows signal VM workflows directly

Do this:

```text
Batch Execution
   |
   +--> VM A
   +--> VM B
   +--> VM C
```

rather than:

```text
Batch Execution
   |
   v
Coordinator
   |
   +--> VM A
   +--> VM B
   +--> VM C
```

Direct result fan-out:

- removes coordinator result traffic;
- reduces coordinator history;
- allows coordinator Continue-As-New independently;
- keeps execution ownership with the batch that produced the result.

---

# 91. Optional coordinator queries

For operations/debugging, the coordinator can expose Query handlers such as:

```text
GetStats
GetBucketSummary
HasRequest(RequestID)
```

Return small summaries only.

Example:

```text
Bucket count
Pending request count
Oldest pending age
Next flush deadline
```

Do not use Query handlers to mutate state.

---

# 92. Optional control signals/updates

Possible operational controls:

```text
flush-bucket
flush-all
pause
resume
```

Only add these if required.

Administrative flush can be valuable during maintenance or configuration migration.

---

# 93. Testing strategy

Test at several levels.

## 93.1 Pure unit tests

Test:

- routing configuration lookup;
- BatchKey canonicalization;
- compatibility hashing;
- BatchExecutionID generation;
- dedup state pruning;
- provider result mapping.

These do not require Temporal.

---

## 93.2 Workflow unit tests

Use Temporal's Go Workflow test environment.

Test:

- one signal creates bucket;
- second compatible signal joins same bucket;
- incompatible request creates separate bucket;
- max size flushes immediately;
- timeout flushes partial bucket;
- duplicate RequestID does not duplicate VM;
- child workflow starts with expected ID;
- result signal correlation;
- Continue-As-New suggestion;
- state snapshot carries deadline.

Temporal Go test support exposes a way to force Continue-As-New suggested state, which is useful for coordinator tests.

---

## 93.3 Replay tests

Capture representative Workflow histories and replay them against new Workflow code before deployment.

This catches nondeterministic workflow changes.

Include histories with:

- multiple buckets;
- timer expiry;
- batch size flush;
- duplicate request;
- Continue-As-New;
- config revisions;
- child starts.

---

## 93.4 Failure tests

Test:

```text
worker dies:
- before batch launch
- after external launch but before Activity completion
- during polling
- immediately before result fan-out
- before Continue-As-New
```

Confirm idempotency behavior.

---

## 93.5 Load tests

Test:

- high signal rate into `batch:ansible`;
- hundreds/thousands of active VM workflows;
- many simultaneous BatchKeys;
- downstream throttling;
- worker rollout;
- coordinator Continue-As-New frequency.

Measure Workflow Task latency.

---

# 94. Example bootstrap

Conceptual service startup:

```go
func ensureCoordinator(
    ctx context.Context,
    c client.Client,
    id string,
    workflowFn interface{},
) error {
    _, err := c.ExecuteWorkflow(
        ctx,
        client.StartWorkflowOptions{
            ID:        id,
            TaskQueue: "workflow-orchestration",
        },
        workflowFn,
        nil,
    )

    if err == nil {
        return nil
    }

    var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
    if errors.As(err, &alreadyStarted) {
        return nil
    }

    return err
}
```

Bootstrap:

```go
ensureCoordinator(ctx, c, "batch:ansible", AnsibleBatchCoordinatorWorkflow)
ensureCoordinator(ctx, c, "batch:odst", ODSTBatchCoordinatorWorkflow)
ensureCoordinator(ctx, c, "batch:dms", DMSBatchCoordinatorWorkflow)
```

Exact start/reuse/conflict options should be chosen to match the deployed Temporal server and operational policy.

---

# 95. End-to-end sequence diagram

```text
VM WF             Resolver          Coordinator        Batch Exec         Provider
 |                   |                  |                   |                |
 |--resolve---------->|                  |                   |                |
 |                   |--read config---->| external/config   |                |
 |<--resolved---------|                  |                   |                |
 |                                      |                   |                |
 |--Signal submit---------------------->|                   |                |
 |                                      | add to bucket     |                |
 |                                      |                   |                |
 |--Signal submit from other VMs------->|                   |                |
 |                                      |                   |                |
 |                                      | size OR timeout   |                |
 |                                      |                   |                |
 |                                      |--start child----->|                |
 |                                      |<--started---------|                |
 |                                      |                   |                |
 |                                      | continue batching |                |
 |                                      |                   |--launch------->|
 |                                      |                   |<--job id-------|
 |                                      |                   |                |
 |                                      |                   |--status------->|
 |                                      |                   |<--running------|
 |                                      |                   |--timer         |
 |                                      |                   |--status------->|
 |                                      |                   |<--complete-----|
 |                                      |                   |                |
 |<-----------------------------------------Signal result----|                |
 |                                      |                   |                |
 | continue VM workflow                 |                   |                |
```

---

# 96. Coordinator state diagram

```text
                     +------------------+
                     | WAITING          |
                     +--------+---------+
                              |
                submit signal | timer expiry
                              v
                     +------------------+
                     | PROCESS EVENT    |
                     +--------+---------+
                              |
                    +---------+---------+
                    |                   |
             bucket not ready      bucket ready
                    |                   |
                    |                   v
                    |          +-------------------+
                    |          | START BATCH EXEC  |
                    |          +---------+---------+
                    |                    |
                    |                    | child started
                    |                    v
                    +--------------> WAITING
                                         |
                                         | history suggestion
                                         v
                                +--------------------+
                                | DRAIN / SNAPSHOT   |
                                +---------+----------+
                                          |
                                 +--------+--------+
                                 |                 |
                              new signal        safe close
                                 |                 |
                                 v                 v
                              WAITING       CONTINUE-AS-NEW
```

---

# 97. Batch Execution state diagram

```text
+---------+
| CREATED |
+----+----+
     |
     v
+-------------+
| LAUNCHING   |
+------+------+
       |
   +---+---+
   |       |
 failure  accepted
   |       |
   v       v
 SIGNAL   MONITORING
 FAILURE     |
             |
        +----+----+
        |         |
      failed    complete
        |         |
        v         v
     SIGNAL     MAP RESULTS
     FAILURE       |
                   v
             SIGNAL CALLERS
                   |
                   v
                COMPLETE
```

---

# 98. What should be shared vs separate in Go code

Recommended:

```text
batch/
  common/
    request.go
    result.go
    id.go
    dedup.go
    canonical.go

  ansible/
    coordinator.go
    execution_workflow.go
    resolver_activity.go
    activities.go
    types.go

  odst/
    coordinator.go
    execution_workflow.go
    activities.go
    types.go

  dms/
    coordinator.go
    execution_workflow.go
    activities.go
    types.go
```

Share helper algorithms.

Keep provider workflows explicit.

Avoid building an overly abstract framework before the three integrations are stable.

---

# 99. Suggested implementation order

## Phase 1 - Core contracts

Implement:

- RequestID rules;
- result signal envelope;
- provider resolved target structures;
- canonical BatchKey;
- deterministic BatchExecutionID.

---

## Phase 2 - Ansible resolver

Implement:

```text
VM env + domain
      |
      v
routing config
      |
      v
primary/secondary
      |
      v
operation.domain.template
      |
      v
ResolvedAnsibleTarget
```

Unit test heavily.

---

## Phase 3 - Ansible coordinator

Implement:

- `batch:ansible`;
- Signal receiver;
- internal buckets;
- max size;
- max wait;
- dedup;
- deterministic iteration;
- child start handoff.

---

## Phase 4 - Ansible Batch Execution

Implement:

- job-template launch;
- workflow-job-template launch;
- external idempotency;
- status monitor;
- per-request result;
- result fan-out.

---

## Phase 5 - Continue-As-New

Implement:

- `GetContinueAsNewSuggested`;
- idle rollover;
- `ReceiveAsync` drain;
- state-carrying rollover;
- absolute deadlines;
- tests.

---

## Phase 6 - ODST

Reuse architectural patterns with an independent coordinator:

```text
batch:odst
```

Add Qualys scan BatchKey and Batch Execution Workflow.

---

## Phase 7 - DMS

Add:

```text
batch:dms
```

Bucket by compatible BoKS host-group-removal operation.

---

## Phase 8 - hardening

Add:

- failure injection;
- replay testing;
- metrics;
- Search Attributes;
- concurrency limits;
- orphan result handling;
- config revision audit.

---

# 100. Production readiness checklist

## Architecture

- [ ] Three coordinator IDs are stable.
- [ ] Flushed batches run in separate execution workflows.
- [ ] Execution children use deterministic Workflow IDs.
- [ ] Execution children are allowed to outlive coordinator runs when required.

## Batch correctness

- [ ] Every common downstream parameter is represented in BatchKey/compatibility hash.
- [ ] VM-specific varying fields are not accidentally included as common fields.
- [ ] Batch deadline starts on first request.
- [ ] Deadline does not reset on subsequent requests.
- [ ] Max size is enforced.
- [ ] More-than-max bucket state is chunked deterministically.

## Dedup

- [ ] RequestID distinguishes logical operation instances.
- [ ] Caller Run ID is not required for request identity.
- [ ] Pending request dedup exists.
- [ ] Recent dedup state is bounded.
- [ ] BatchExecutionID is deterministic.
- [ ] Child Workflow ID uses BatchExecutionID.
- [ ] Downstream launch reuses BatchExecutionID on retries.

## Centralized monitoring

- [ ] A Batch Execution Workflow owns each external Job/Scan/Operation ID.
- [ ] VM workflows never independently poll a shared external execution ID.
- [ ] One provider status call occurs per batch polling interval.
- [ ] Progress signals use stable signal name plus `RequestID` correlation.
- [ ] Caller logs non-terminal progress and waits again.
- [ ] Terminal state releases caller success/failure flow.
- [ ] Terminal status is always notified immediately.
- [ ] Unchanged RUNNING notifications are throttled by default, unless every-poll notification is explicitly required.
- [ ] `PollSequence` and `LastPolledAt` are included for monitoring visibility.
- [ ] Per-host final outcomes override coarse batch-wide failure when authoritative host-level results exist.
- [ ] Very long Batch Execution Workflows can Continue-As-New while preserving the same external execution ID.

## Continue-As-New

- [ ] Uses `GetContinueAsNewSuggested`.
- [ ] Idle rollover is preferred.
- [ ] Go signal channel is drained with `ReceiveAsync`.
- [ ] No blocking/yield occurs after final drain before Continue-As-New.
- [ ] Busy rollover can carry bucket state.
- [ ] Flush deadlines are absolute and preserved.
- [ ] Dedup state required across rollover is carried.
- [ ] Detached execution workflows do not depend on old coordinator Run ID.

## Determinism

- [ ] No native timers in Workflow code.
- [ ] No native goroutines/channels/select.
- [ ] No direct network/database/filesystem reads from Workflow code.
- [ ] No direct mutable env config reads.
- [ ] Map iteration is sorted before behavior-affecting decisions.
- [ ] Workflow clock uses `workflow.Now`.
- [ ] IDs are deterministic.

## Reliability

- [ ] External launch has idempotency/correlation.
- [ ] Retryable vs non-retryable errors are classified.
- [ ] Orphan result policy exists.
- [ ] Partial host failure is supported.
- [ ] Worker restart tests exist.
- [ ] Activity crash-after-external-accept test exists.

## Security

- [ ] No credentials in Workflow history.
- [ ] Provider Activities obtain secrets at runtime.
- [ ] Logs do not expose secrets.
- [ ] Error payloads do not accidentally contain credentials.

## Operations

- [ ] Coordinators are bootstrapped.
- [ ] Multiple workers may poll safely.
- [ ] Metrics exist.
- [ ] Search Attributes are defined where useful.
- [ ] Replay tests run before incompatible workflow deployments.
- [ ] Load test verifies one Ansible coordinator is sufficient.

---


# 101. Final recommended architecture

```text
                           MANY VM WORKFLOWS
                                  |
                   +--------------+--------------+
                   |              |              |
                   v              v              v
                ANSIBLE          ODST            DMS
                   |              |              |
           Resolve target          |              |
                   |              |              |
                   v              v              v
          +---------------+ +------------+ +------------+
          | batch:ansible | | batch:odst | | batch:dms  |
          +-------+-------+ +-----+------+ +------+-----+
                  |               |               |
            internal buckets internal buckets internal buckets
                  |               |               |
           size OR timeout  size OR timeout size OR timeout
                  |               |               |
                  +-------+-------+-------+-------+
                          |               |
                          v               v
                  BatchExecutionWorkflow
                          |
                          | launch exactly once
                          v
              +-----------+------------+
              |           |            |
              v           v            v
           Ansible       ODST          DMS
        Primary/Secondary |             |
              |         Qualys         BoKS
              |
              v
        external execution ID
              |
              v
      CENTRALIZED POLLING ONCE
          PER BATCH INTERVAL
              |
       +------+------+------------------+
       |             |                  |
       v             v                  v
    PENDING        RUNNING            TERMINAL
       |             |                  |
       |      state-change signal        |
       |      or heartbeat signal        |
       |             |                  |
       +------+------+------------------+
              |
              v
       BatchExecutionWorkflow
       fans status to callers
              |
       +------+------+------+
       |             |      |
       v             v      v
     VM WF A       VM WF B VM WF N
       |             |      |
 RUNNING: log      log     log
 and wait again     |       |
       |             |      |
 TERMINAL: resume success/failure flow
```

The caller workflows are observers of the centralized monitor; they are not pollers of the downstream system.

---

# 102. Key principles to preserve during implementation

1. **Resolve before batching.**
2. **Batch by downstream compatibility, not by arbitrary business labels.**
3. **Keep Ansible, ODST, and DMS coordinators separate.**
4. **Use one Ansible coordinator with internal resolved-template buckets.**
5. **Use RequestID for request dedup, not Workflow ID alone.**
6. **Use deterministic BatchExecutionID for each flushed operation.**
7. **Use separate execution workflows so coordinators remain responsive.**
8. **One Batch Execution Workflow owns each downstream Job/Scan/Operation ID.**
9. **Poll each downstream execution once per batch interval, never once per VM workflow.**
10. **Fan non-terminal progress signals to callers for logging/visibility.**
11. **Callers receiving `PENDING`/`RUNNING` log the update and wait again.**
12. **Callers receiving terminal status resume their success/failure business flow.**
13. **Always notify terminal state immediately.**
14. **Support every-poll progress signaling, but throttle unchanged `RUNNING` heartbeats by default to control history growth.**
15. **Include polling metadata such as PollSequence and LastPolledAt when progress visibility matters.**
16. **Prefer per-host terminal results over a coarse batch-wide result when provider data supports it.**
17. **Use downstream idempotency because Activities can retry.**
18. **Continue-As-New coordinator workflows before histories become large.**
19. **Drain Go signal channels immediately before coordinator Continue-As-New.**
20. **Carry absolute bucket deadlines across coordinator Continue-As-New.**
21. **Allow very long Batch Execution Workflows to Continue-As-New while retaining the same external execution ID and never relaunching it.**
22. **Rely on Temporal history/replay for workflow recovery after worker restart.**
23. **Never put secrets in Temporal workflow state/history.**
24. **Keep all Workflow decisions deterministic.**
25. **Measure the single Ansible coordinator before considering sharding.**

---

# 103. Temporal references

The following official/current documentation is particularly relevant to the design:

- Temporal Workflows and replay:  
  https://docs.temporal.io/workflows

- Event History and recovery:  
  https://docs.temporal.io/encyclopedia/event-history

- Go SDK developer guide:  
  https://docs.temporal.io/develop/go

- Go Continue-As-New:  
  https://docs.temporal.io/develop/go/workflows/continue-as-new

- Child Workflows and Parent Close Policy:  
  https://docs.temporal.io/child-workflows

- Worker deployment / Event History management:  
  https://docs.temporal.io/best-practices/worker

- Temporal tasks / Activity execution semantics:  
  https://docs.temporal.io/tasks

- Temporal Go SDK workflow API:  
  https://pkg.go.dev/go.temporal.io/sdk/workflow

- Temporal Go SDK client API:  
  https://pkg.go.dev/go.temporal.io/sdk/client

- Go signal-channel draining discussion (`ReceiveAsync` before Continue-As-New):  
  https://community.temporal.io/t/continueasnew-signals/1008

---


# 103.1 Current Temporal mechanics relevant to centralized polling

The design relies on these Temporal behaviors:

- `workflow.SignalExternalWorkflow` can target the currently running execution by using the Workflow ID and an empty Run ID.
- Signals create Workflow History work; therefore high-frequency progress fan-out should be treated as a history/throughput decision.
- `Continue-As-New` keeps the Workflow ID, creates a new Run ID, and starts a fresh Event History.
- Workflow code should use `workflow.GetLogger`, Temporal timers/channels/selectors, and deterministic iteration practices.

These mechanics are why centralized polling plus controlled progress fan-out is preferable to making every caller poll the same external Job ID.

---

# 104. Implementation note

The code snippets in this document are architecture-oriented skeletons. Before production use:

- align exact API calls with the Temporal Go SDK version pinned by the project;
- define provider-specific request/response structures;
- define actual Ansible, ODST, Qualys, DMS, and BoKS API semantics;
- test replay compatibility;
- verify downstream idempotency capabilities;
- define provider rate limits and operation-specific timeout/retry policies.

The architectural invariants in this document should remain valid even when those provider details are filled in.
