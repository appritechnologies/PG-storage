# GCS S3 Interoperability Fixes

Google Cloud Storage (GCS) in S3 interoperability mode does not fully support all S3 APIs. This document covers all changes made to ensure Supabase Storage works correctly with GCS as the storage backend.

## Required Environment Variables

```env
STORAGE_S3_DISABLE_CHECKSUM=true
TUS_ALLOW_S3_TAGS=false
```

| Variable | Purpose |
|----------|---------|
| `STORAGE_S3_DISABLE_CHECKSUM=true` | Disables AWS SDK v3 automatic checksum headers (`x-amz-checksum-*`) that GCS does not understand, causing `SignatureDoesNotMatch` errors |
| `TUS_ALLOW_S3_TAGS=false` | Disables S3 object tagging on TUS uploads. GCS does not support the S3 tagging API |

---

## Fix 1: S3Backend.deleteObjects() fallback for batch delete

**File:** `src/storage/backend/s3/adapter.ts`
**Method:** `S3Backend.deleteObjects()`

### Problem

GCS does not implement the `DeleteObjects` (batch delete) S3 API (`POST ?delete`). All batch delete operations fail with:

```
NotImplemented: POST ?delete is not implemented for objects.
```

This breaks:
- Deleting objects from Supabase Studio UI
- Batch delete API endpoint
- Admin object deletion events (ObjectAdminDelete)
- Bulk deletion by date (ObjectAdminDeleteAllBefore)
- S3 protocol delete endpoint

### Solution

When `DeleteObjectsCommand` returns `NotImplemented`, automatically fall back to individual `DeleteObjectCommand` calls in parallel.

```
batch DeleteObjects --> NotImplemented
  |
  v (fallback)
individual DeleteObject x N (in parallel via Promise.allSettled)
```

- `NoSuchKey` errors are silently ignored (idempotent behavior)
- Real errors (e.g. `AccessDenied`) are re-thrown
- Non-`NotImplemented` errors bypass the fallback entirely
- Standard S3 (AWS) and MinIO are unaffected

### Call sites covered by this fix

| Call Site | File | Description |
|-----------|------|-------------|
| REST API | `src/http/routes/object/deleteObjects.ts` | Direct REST deletion endpoint |
| ObjectStorage | `src/storage/object.ts` | Syncs DB deletion to S3 |
| ObjectAdminDelete | `src/storage/events/objects/object-admin-delete.ts` | Admin single object deletion event |
| ObjectAdminDeleteAllBefore | `src/storage/events/objects/object-admin-delete-all-before.ts` | Admin bulk deletion by date event |
| S3 Protocol | `src/storage/protocols/s3/s3-handler.ts` | S3-compatible batch delete endpoint |
| TUS uploads (indirect) | `src/storage/uploader.ts` | Upload failure cleanup and version overwrite via ObjectAdminDelete event |

---

## Fix 2: S3Locker.cleanupZombieLocks() fallback for batch delete

**File:** `src/storage/protocols/tus/s3-locker.ts`
**Method:** `S3Locker.cleanupZombieLocks()`

### Problem

The TUS S3 locker uses its own `S3Client` instance and calls `DeleteObjectsCommand` directly to clean up expired lock objects. This bypasses `S3Backend.deleteObjects()` and its fallback logic. On GCS, the periodic zombie lock cleanup fails silently, causing expired lock objects to accumulate indefinitely.

### Solution

Applied the same fallback pattern inside `cleanupZombieLocks()`:

1. Try `DeleteObjectsCommand` (batch)
2. On `NotImplemented`, fall back to individual `DeleteObjectCommand` calls in parallel
3. `NoSuchKey` errors are ignored
4. Real failures are logged as warnings

### Other S3Locker methods (no fix needed)

- `releaseLock()` -- uses singular `DeleteObjectCommand` -- works on GCS
- `checkAndCleanupExpiredLock()` -- uses singular `DeleteObjectCommand` -- works on GCS
- `acquireLock()`, `renewLock()` -- use `PutObjectCommand`/`GetObjectCommand` -- work on GCS

---

## Fix 3: TUS S3Store and S3Locker checksum disable

**File:** `src/http/routes/tus/index.ts`

### Problem

AWS SDK v3 (starting around v3.729) changed the default checksum behavior from `WHEN_REQUIRED` to `WHEN_SUPPORTED`. This means the SDK automatically adds `x-amz-checksum-crc32` headers to requests. GCS does not include these headers in its signature calculation, causing:

```
SignatureDoesNotMatch: The request signature we calculated does not match
the signature you provided. Check your Google secret key and signing method.
```

The main `S3Backend` already had a fix for this (`storageS3DisableChecksum` config, applied in `src/storage/backend/s3/adapter.ts:630-632`). However, the TUS S3Store and S3Locker create their own S3 clients and never received this setting.

### What broke and when

The `@aws-sdk/client-s3` dependency was bumped from `^3.948.0` to `^3.979.0` (resolving to `3.1003.0`) in the security advisory fix commit. This pulled in the new default checksum behavior. Regular uploads via `S3Backend` still worked (if `STORAGE_S3_DISABLE_CHECKSUM=true` was set), but TUS resumable uploads broke because the TUS S3Store's client was not configured with the checksum override.

### Solution

Propagated `storageS3DisableChecksum` to both S3 clients in the TUS setup:

1. **TUS S3Store `s3ClientConfig`** -- added `requestChecksumCalculation: 'WHEN_REQUIRED'` and `responseChecksumValidation: 'WHEN_REQUIRED'` when `storageS3DisableChecksum` is true
2. **S3Locker `S3Client`** -- same addition

The settings are conditionally spread so that standard S3/MinIO deployments (where `STORAGE_S3_DISABLE_CHECKSUM` is not set) are unaffected.

---

## Files Changed (Summary)

| File | Change |
|------|--------|
| `src/storage/backend/s3/adapter.ts` | `deleteObjects()`: fallback from batch to individual deletes on `NotImplemented` |
| `src/storage/protocols/tus/s3-locker.ts` | `cleanupZombieLocks()`: same batch-to-individual fallback |
| `src/http/routes/tus/index.ts` | Propagate `storageS3DisableChecksum` to TUS S3Store and S3Locker S3 clients |

## Test Coverage

**File:** `src/test/s3-adapter.test.ts`

| Test | Description |
|------|-------------|
| Batch delete works | Verifies `DeleteObjectsCommand` is used when backend supports it |
| Fallback on NotImplemented | Verifies individual `DeleteObjectCommand` calls when batch returns `NotImplemented` |
| NoSuchKey ignored | Verifies `NoSuchKey` errors are silently ignored in fallback |
| Real errors throw | Verifies real errors (e.g. `AccessDenied`) are re-thrown in fallback |
| Non-NotImplemented rethrown | Verifies errors other than `NotImplemented` bypass the fallback |
