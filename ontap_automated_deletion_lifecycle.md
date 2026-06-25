# ONTAP REST API: Complete In-Memory Discovery & Volume Deletion Lifecycle Guide

This document provides a comprehensive, production-ready operational blueprint for automating the deletion of pre-offlined NetApp ONTAP volumes. It details how to handle environments containing a mix of both Source (RW) and Destination (DP) volumes using optimized, in-memory lookups to match Volume UUIDs with SnapMirror paths (`svm:volume`).

---

## 1. Master Architecture & Operational Flow

```text
========================================================================================================================
                                     ONTAP REST API: IN-MEMORY DISCOVERY & CLEANUP LIFECYCLE
========================================================================================================================

          [ STEP 1: Fetch Bulk Data ]
          Array_Standard = GET /api/snapmirror/relationships
          Array_DestOnly = GET /api/snapmirror/relationships?list_destinations_only=true
          Array_Volumes  = GET /api/storage/volumes?fields=svm.name,name
                                                 │
                                                 ▼
                             [ STEP 2: Map UUIDs to Path Strings In-Memory ]
                             Build map dictionary: { volume_uuid: "svm_name:volume_name" }
                                                 │
                                                 ▼
                             [ STEP 3: Search Loop (Per Target Volume) ]
                             Does your target constructed path exist in Array_Standard or Array_DestOnly?
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼ Yes                                             ▼ No
       Where is the constructed path found?                         [ STEP 4: Safe Delete ]
                        │                                           Volume has no mirrors.
       ┌────────────────┴────────────────┐                          Proceed straight to:
       ▼ Found in Array_Standard         ▼ Found ONLY in Array_DestOnly  DELETE /api/storage/volumes/{id}
    Evaluate path object properties:     (or as "source.path" in Standard)
       │                                         │
       ├─► Matches "source.path" ────────┘       │
       │                                         ▼
       └─► Matches "destination.path" ──┐   VOLUME IS THE SOURCE
                    │                   └────────┬────────────────┘
                    ▼                            │
       ┌─────────────────────────┐               ▼
       │  VOLUME IS DESTINATION  │    [ STEP A1: Bring Vol ONLINE ]
       └────────────┬────────────┘    PATCH /api/storage/volumes/{uuid}
                    │                     { "state": "online" }
                    ▼                            │
       [ STEP B1: Delete Mirror ]                ▼
       DELETE /api/snapmirror/        [ STEP A2: Delete/Release Mirror ]
       relationships/{uuid}?force=trueDELETE /api/snapmirror/relationships/{uuid}?source_only=true
                    │                            │
                    ▼                            ▼
       [ STEP B2: Delete Volume ]     [ STEP A3: Take Vol OFFLINE ]
       DELETE /api/storage/           PATCH /api/storage/volumes/{uuid}
       volumes/{uuid}                     { "state": "offline" }
                    │                            │
                    ▼                            ▼
             [ WORKFLOW END ]         [ STEP A4: Delete Volume ]
                                      DELETE /api/storage/volumes/{uuid}
                                                 │
                                                 ▼
                                          [ WORKFLOW END ]
========================================================================================================================
```

---

## 2. Step-by-Step Implementation Logic

### Step 1: Initialize & Cache Datasets (Bulk Fetch)
To minimize API overhead, query the cluster endpoints once up front to pull down all metadata into your local execution memory:
1. **Cache Volumes:** `Array_Volumes = GET /api/storage/volumes?fields=svm.name,name`
2. **Cache Standard Relationships:** `Array_Standard = GET /api/snapmirror/relationships`
3. **Cache Outbound-Only Pipelines:** `Array_DestOnly = GET /api/snapmirror/relationships?list_destinations_only=true`
4. **Identify Target Array:** Set `Target_Volumes = [ "volume_uuid_1", "volume_uuid_2", ... ]`

### Step 2: Build the Path Lookup Dictionary
Loop through your `Array_Volumes` response and build a fast hash-map structure. Because the SnapMirror endpoint tracks relationships using string-based path configurations (`svm_name:volume_name`) instead of underlying volume UUIDs, this dictionary translates your local UUIDs to their corresponding paths instantly:
* **Key:** `volume.uuid`
* **Value:** `"volume.svm.name:volume.name"`

*Example Mapping Object:*
```json
{
  "85b1a3c2-12ef-45ab-9cd7-112233445566": "SvmProduction:Vol_Database_Prod",
  "92c4d5e6-34fe-56ba-0fe8-778899aabbcc": "SvmDisasterRecovery:Vol_Database_Mirror"
}
```

### Step 3: Loop & Role Assignment Algorithm
For every separate `target_uuid` listed within your `Target_Volumes` selection array, fetch its mapped path value from your lookup dictionary: `Constructed_Path = Volume_Path_Map[target_uuid]`. 

Evaluate its presence across your dataset caches sequentially:

1. **Check Condition 1 (Destination Role Evaluation):**
   * Scan through `Array_Standard`. 
   * Look for a data record where `item.destination.path == Constructed_Path`.
   * **Result:** If a match triggers, store the matching `item.uuid` as your `relationship_uuid`. Set your tracking status to `Volume_Role = "DESTINATION"`. Immediately terminate searching for this volume and skip directly to **Step 4: Execution Matrix**.

2. **Check Condition 2 (Source Role Evaluation):**
   * If Condition 1 did not find a match, search both:
     * **A)** `Array_Standard` for a record where `item.source.path == Constructed_Path`.
     * **B)** `Array_DestOnly` for a record where `item.source.path == Constructed_Path`.
   * **Result:** If a match triggers in either collection list, store the matching `item.uuid` as your `relationship_uuid`. Set your tracking status to `Volume_Role = "SOURCE"`. Immediately terminate searching for this volume and skip directly to **Step 4: Execution Matrix**.

3. **Check Condition 3 (Fallback Unreplicated Assignment):**
   * If the `Constructed_Path` was not successfully located across any relationship arrays.
   * **Result:** Set your tracking status to `Volume_Role = "UNREPLICATED"`. Proceed straight to **Step 4: Execution Matrix**.

---

## 3. Detailed REST API Execution Specifications

### BRANCH A: Volume determined to be a DESTINATION

*Use Case Description: The pre-offlined volume serves strictly as a mirror replica endpoint. Because its data flow points inbound, its metadata ties can be dropped cleanly without turning the file system back online.*

#### 1. Sever and Erase SnapMirror Configuration Record
* **HTTP Method:** `DELETE`
* **URL String:** `https://<cluster-management-ip>/api/snapmirror/relationships/{relationship_uuid}?force=true`
* **JSON Body:** *None*
* **Parameter Breakdown:** Appending `?force=true` tells the ONTAP storage orchestrator to drop the metadata mapping structure instantly, bypassing unmounted storage block verification errors or inter-cluster communication paths.

#### 2. Permanently Delete Volume Assets
* **HTTP Method:** `DELETE`
* **URL String:** `https://<cluster-management-ip>/api/storage/volumes/{target_uuid}`
* **JSON Body:** *None*

---

### BRANCH B: Volume determined to be a SOURCE

*Use Case Description: The volume serves as a production origin. It owns hidden active SnapMirror tracking block snapshots (`snapmirror.xxx`) locking down your underlying aggregates. You must temporarily remount the volume so ONTAP can clean up those internal snapshot references.*

#### 1. Temporarily Transition Volume State to Online
* **HTTP Method:** `PATCH`
* **URL String:** `https://<cluster-management-ip>/api/storage/volumes/{target_uuid}`
* **JSON Payload Format:**
```json
{
  "state": "online"
}
```

#### 2. Release Source Tracking Snapshots & Erase Local Mapping Metadata
* **HTTP Method:** `DELETE`
* **URL String:** `https://<cluster-management-ip>/api/snapmirror/relationships/{relationship_uuid}?source_only=true`
* **JSON Body:** *None*
* **Parameter Breakdown:** Appending `?source_only=true` ensures the command is isolated to a strictly local operation. It deletes the tracking snapshot dependencies inside your newly onlined volume blocks and erases the relationship footprint without attempting outbound network requests over peer paths that could hang or timeout.

#### 3. Unmount and Return Volume to Offline State
* **HTTP Method:** `PATCH`
* **URL String:** `https://<cluster-management-ip>/api/storage/volumes/{target_uuid}`
* **JSON Payload Format:**
```json
{
  "state": "offline"
}
```

#### 4. Permanently Delete Volume Assets
* **HTTP Method:** `DELETE`
* **URL String:** `https://<cluster-management-ip>/api/storage/volumes/{target_uuid}`
* **JSON Body:** *None*

---

### BRANCH C: Volume determined to be UNREPLICATED

*Use Case Description: The volume has no active SnapMirror metadata relationships attached.*

#### 1. Permanently Delete Volume Assets Directly
* **HTTP Method:** `DELETE`
* **URL String:** `https://<cluster-management-ip>/api/storage/volumes/{target_uuid}`
* **JSON Body:** *None*

---

## 4. Architectural Summary Cheat Sheet

| Evaluated Role | Execution Sequence | HTTP Method | Query Parameters | Core Functional Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **DESTINATION** | 1. Sever Mirror | `DELETE` | `?force=true` | Forcefully strips metadata without mounting volume blocks. |
| | 2. Destroy Storage | `DELETE` | *None* | Wipes out the offline volume and reclaims aggregate space. |
| **SOURCE** | 1. Mount Storage | `PATCH` | *None* | Sets volume to `"online"`, allowing ONTAP internal structural access. |
| | 2. Release Mirror | `DELETE` | `?source_only=true` | Deletes base tracking snapshots locally and avoids peer timeouts. |
| | 3. Unmount Storage| `PATCH` | *None* | Flips volume back to `"offline"` to remove operational locks. |
| | 4. Destroy Storage | `DELETE` | *None* | Wipes out the unmounted volume and reclaims aggregate space. |
| **UNREPLICATED**| 1. Destroy Storage | `DELETE` | *None* | Deletes isolated offline asset immediately without prerequisites. |

---

## 5. Engineering Scripting Guidelines
* **Avoid Gateway Saturation:** Do not place Step 1 bulk collection calls inside multi-threaded or nested loops. Fetch the data collections once serially at the top of your execution script run, and leverage your local memory for searching.
* **Volume State Lock Retries:** When shifting a Source volume from **Step B2 to Step B3** (turning the volume back offline after snapshot release), you should expect a potential race condition. ONTAP background worker processes sometimes take a few seconds to fully finalize block allocation metadata files after a snapshot is deleted. Implement a **3-to-5 second exponential backoff / retry loop** on that specific `PATCH` call to handle transient volume resource busy errors seamlessly.
