from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import base64
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from delivery_system.attestation import (
    AttestationContractError,
    AttestationRuntimeBoundary,
    RevocationStatus,
)
from delivery_system.attestation_persistence import (
    ATTESTATION_REVALIDATION_FAILURE_CODES,
    AttestationRevalidationEvent,
    PersistenceContractError,
    RevalidationAttemptBoundary,
)
from delivery_system.attestation_persistence_store import (
    AttestationArtifactAggregate,
    InMemoryAttestationPersistenceStore,
    SQLiteAttestationPersistenceStore,
    StoreContractError,
)
import delivery_system.attestation_restart as restart_module
from delivery_system.attestation_restart import (
    RestartRevalidationError,
    RestartRevalidationResult,
    RestartRevalidationService,
    _build_restart_revalidation_context_payload,
    _derive_restart_revalidation_context_digest,
)
from delivery_system.protocol import canonical_payload, digest, normalize
from tests.fakes.attestation_persistence_store_contract import (
    artifact_for,
    reference_for,
)


NOW = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
EXPECTED_CONTEXT_DIGEST = (
    "sha256:c0721b3bb6f9a33b694c55fca4b465663138c35b173dfb029c1913128c3aa47e"
)
SERVICE_CODES = (
    "attestation_restart_identity_mismatch",
    "attestation_restart_attempt_invalid",
    "attestation_restart_context_invalid",
    "attestation_restart_revocation_unknown",
    "attestation_restart_revocation_unavailable",
    "attestation_restart_revocation_invalid",
    "attestation_restart_clock_invalid",
)


GOLDEN_FIXTURE_ID = "slice_d_revalidation_context_v1_golden_001"
GOLDEN_RAW_JSON = "{\"domain\":\"delivery-system:attestation-revalidation-context:v1\",\"payload_version\":\"1\",\"workspace_identity\":\"workspace-1\",\"artifact\":{\"artifact_contract_version\":\"offline-attestation-artifact-v1\",\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_digest\":\"sha256:90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_payload\":{\"domain\":\"delivery-system:credential-capability-attestation:v1\",\"claims\":{\"attestation_version\":\"1\",\"issuer_id\":\"issuer-1\",\"key_id\":\"key-1\",\"signature_algorithm\":\"ed25519\",\"credential_class\":\"github-app-installation-token\",\"credential_instance_id\":\"credential-instance-1\",\"github_subject_identity\":\"subject-node-1\",\"repository_identity\":\"owner/repository\",\"granted_capabilities\":[\"issues:read\",\"issues:write\"],\"driver_identity\":\"github-rest-driver-v1\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"preview_id\":\"preview-1\",\"revision\":1,\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"issued_at\":\"2026-08-14T11:00:00Z\",\"expires_at\":\"2026-08-14T13:00:00Z\",\"nonce\":\"nonce-1\",\"source_verification_digest\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\"}},\"created_at\":\"2026-08-14T11:31:00.000000Z\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"workspace_identity\":\"workspace-1\"},\"binding_reference\":{\"reference_contract_version\":\"attestation-binding-reference-v1\",\"reference_id\":\"binding-reference-6540147e60af24b1ccca41295109099e02bc88007ca7b29f4811efe20781be66\",\"workspace_identity\":\"workspace-1\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"binding_id\":\"binding-1111111111111111111111111111111111111111111111111111111111111111\",\"repository_identity\":\"owner/repository\",\"github_subject_identity\":\"subject-node-1\",\"driver_identity\":\"github-rest-driver-v1\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"preview_id\":\"preview-1\",\"revision\":1,\"plan_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"sealed_preview_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"audit_id\":\"audit-1\",\"audit_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"evidence_id\":\"evidence-1\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"binding_reference_digest\":\"sha256:68786a166a8f123b98c88eeb10c05752cac3b63e9fd7c0c4d56f11fe675c619a\"}}"
GOLDEN_NORMALIZED_JSON = "{\"artifact\":{\"artifact_contract_version\":\"offline-attestation-artifact-v1\",\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_digest\":\"sha256:90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_payload\":{\"claims\":{\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"attestation_version\":\"1\",\"credential_class\":\"github-app-installation-token\",\"credential_instance_id\":\"credential-instance-1\",\"driver_identity\":\"github-rest-driver-v1\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"expires_at\":\"2026-08-14T13:00:00Z\",\"github_subject_identity\":\"subject-node-1\",\"granted_capabilities\":[\"issues:read\",\"issues:write\"],\"issued_at\":\"2026-08-14T11:00:00Z\",\"issuer_id\":\"issuer-1\",\"key_id\":\"key-1\",\"nonce\":\"nonce-1\",\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"preview_id\":\"preview-1\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"repository_identity\":\"owner/repository\",\"revision\":1,\"signature_algorithm\":\"ed25519\",\"source_verification_digest\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"},\"domain\":\"delivery-system:credential-capability-attestation:v1\"},\"created_at\":\"2026-08-14T11:31:00.000000Z\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"workspace_identity\":\"workspace-1\"},\"binding_reference\":{\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"audit_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"audit_id\":\"audit-1\",\"binding_id\":\"binding-1111111111111111111111111111111111111111111111111111111111111111\",\"binding_reference_digest\":\"sha256:68786a166a8f123b98c88eeb10c05752cac3b63e9fd7c0c4d56f11fe675c619a\",\"driver_identity\":\"github-rest-driver-v1\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"evidence_id\":\"evidence-1\",\"github_subject_identity\":\"subject-node-1\",\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"plan_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"preview_id\":\"preview-1\",\"reference_contract_version\":\"attestation-binding-reference-v1\",\"reference_id\":\"binding-reference-6540147e60af24b1ccca41295109099e02bc88007ca7b29f4811efe20781be66\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"repository_identity\":\"owner/repository\",\"revision\":1,\"sealed_preview_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"workspace_identity\":\"workspace-1\"},\"domain\":\"delivery-system:attestation-revalidation-context:v1\",\"payload_version\":\"1\",\"workspace_identity\":\"workspace-1\"}"
GOLDEN_CANONICAL_JSON = "{\"artifact\":{\"artifact_contract_version\":\"offline-attestation-artifact-v1\",\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_digest\":\"sha256:90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"claims_payload\":{\"claims\":{\"attestation_id\":\"attestation-90b7a4496b3f162a3dfdd641744959c12fb8bbfc7da4ea030fc5ab31920c10f2\",\"attestation_version\":\"1\",\"credential_class\":\"github-app-installation-token\",\"credential_instance_id\":\"credential-instance-1\",\"driver_identity\":\"github-rest-driver-v1\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"expires_at\":\"2026-08-14T13:00:00Z\",\"github_subject_identity\":\"subject-node-1\",\"granted_capabilities\":[\"issues:read\",\"issues:write\"],\"issued_at\":\"2026-08-14T11:00:00Z\",\"issuer_id\":\"issuer-1\",\"key_id\":\"key-1\",\"nonce\":\"nonce-1\",\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"preview_id\":\"preview-1\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"repository_identity\":\"owner/repository\",\"revision\":1,\"signature_algorithm\":\"ed25519\",\"source_verification_digest\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"},\"domain\":\"delivery-system:credential-capability-attestation:v1\"},\"created_at\":\"2026-08-14T11:31:00.000000Z\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"workspace_identity\":\"workspace-1\"},\"binding_reference\":{\"artifact_digest\":\"sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb\",\"artifact_id\":\"artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec\",\"audit_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"audit_id\":\"audit-1\",\"binding_id\":\"binding-1111111111111111111111111111111111111111111111111111111111111111\",\"binding_reference_digest\":\"sha256:68786a166a8f123b98c88eeb10c05752cac3b63e9fd7c0c4d56f11fe675c619a\",\"driver_identity\":\"github-rest-driver-v1\",\"evidence_digest\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"evidence_id\":\"evidence-1\",\"github_subject_identity\":\"subject-node-1\",\"operation_set_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"original_verified_at\":\"2026-08-14T11:30:00.000000Z\",\"plan_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"preview_id\":\"preview-1\",\"reference_contract_version\":\"attestation-binding-reference-v1\",\"reference_id\":\"binding-reference-6540147e60af24b1ccca41295109099e02bc88007ca7b29f4811efe20781be66\",\"remote_authority\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"remote_snapshot_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"repository_identity\":\"owner/repository\",\"revision\":1,\"sealed_preview_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"workspace_identity\":\"workspace-1\"},\"domain\":\"delivery-system:attestation-revalidation-context:v1\",\"payload_version\":\"1\",\"workspace_identity\":\"workspace-1\"}"
GOLDEN_UTF8_BASE64 = "eyJhcnRpZmFjdCI6eyJhcnRpZmFjdF9jb250cmFjdF92ZXJzaW9uIjoib2ZmbGluZS1hdHRlc3RhdGlvbi1hcnRpZmFjdC12MSIsImFydGlmYWN0X2RpZ2VzdCI6InNoYTI1NjowYWE4NDk1MDNlODNmOWJlOTY4Y2ZjNzc1M2YxNGM2OWE0OTM1MjQzY2YxZmQ0MzI0ZWNmMDk0ZWJkZjhiZWViIiwiYXJ0aWZhY3RfaWQiOiJhcnRpZmFjdC03MzRkM2U3YTk1ZDM0ZGI1ZjM4ODBiYjc2OWE1NzdjOGRkNzZiMzQ4NjliOGRhNDFmMDc2NDg3YzUwNjc2ZGVjIiwiYXR0ZXN0YXRpb25faWQiOiJhdHRlc3RhdGlvbi05MGI3YTQ0OTZiM2YxNjJhM2RmZGQ2NDE3NDQ5NTljMTJmYjhiYmZjN2RhNGVhMDMwZmM1YWIzMTkyMGMxMGYyIiwiY2xhaW1zX2RpZ2VzdCI6InNoYTI1Njo5MGI3YTQ0OTZiM2YxNjJhM2RmZGQ2NDE3NDQ5NTljMTJmYjhiYmZjN2RhNGVhMDMwZmM1YWIzMTkyMGMxMGYyIiwiY2xhaW1zX3BheWxvYWQiOnsiY2xhaW1zIjp7ImF0dGVzdGF0aW9uX2lkIjoiYXR0ZXN0YXRpb24tOTBiN2E0NDk2YjNmMTYyYTNkZmRkNjQxNzQ0OTU5YzEyZmI4YmJmYzdkYTRlYTAzMGZjNWFiMzE5MjBjMTBmMiIsImF0dGVzdGF0aW9uX3ZlcnNpb24iOiIxIiwiY3JlZGVudGlhbF9jbGFzcyI6ImdpdGh1Yi1hcHAtaW5zdGFsbGF0aW9uLXRva2VuIiwiY3JlZGVudGlhbF9pbnN0YW5jZV9pZCI6ImNyZWRlbnRpYWwtaW5zdGFuY2UtMSIsImRyaXZlcl9pZGVudGl0eSI6ImdpdGh1Yi1yZXN0LWRyaXZlci12MSIsImV2aWRlbmNlX2RpZ2VzdCI6InNoYTI1NjpkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIiwiZXhwaXJlc19hdCI6IjIwMjYtMDgtMTRUMTM6MDA6MDBaIiwiZ2l0aHViX3N1YmplY3RfaWRlbnRpdHkiOiJzdWJqZWN0LW5vZGUtMSIsImdyYW50ZWRfY2FwYWJpbGl0aWVzIjpbImlzc3VlczpyZWFkIiwiaXNzdWVzOndyaXRlIl0sImlzc3VlZF9hdCI6IjIwMjYtMDgtMTRUMTE6MDA6MDBaIiwiaXNzdWVyX2lkIjoiaXNzdWVyLTEiLCJrZXlfaWQiOiJrZXktMSIsIm5vbmNlIjoibm9uY2UtMSIsIm9wZXJhdGlvbl9zZXRfZGlnZXN0Ijoic2hhMjU2OmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJwcmV2aWV3X2lkIjoicHJldmlldy0xIiwicmVtb3RlX2F1dGhvcml0eSI6InNoYTI1NjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwicmVtb3RlX3NuYXBzaG90X2RpZ2VzdCI6InNoYTI1NjpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjIiwicmVwb3NpdG9yeV9pZGVudGl0eSI6Im93bmVyL3JlcG9zaXRvcnkiLCJyZXZpc2lvbiI6MSwic2lnbmF0dXJlX2FsZ29yaXRobSI6ImVkMjU1MTkiLCJzb3VyY2VfdmVyaWZpY2F0aW9uX2RpZ2VzdCI6InNoYTI1NjplZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlIn0sImRvbWFpbiI6ImRlbGl2ZXJ5LXN5c3RlbTpjcmVkZW50aWFsLWNhcGFiaWxpdHktYXR0ZXN0YXRpb246djEifSwiY3JlYXRlZF9hdCI6IjIwMjYtMDgtMTRUMTE6MzE6MDAuMDAwMDAwWiIsIm9yaWdpbmFsX3ZlcmlmaWVkX2F0IjoiMjAyNi0wOC0xNFQxMTozMDowMC4wMDAwMDBaIiwid29ya3NwYWNlX2lkZW50aXR5Ijoid29ya3NwYWNlLTEifSwiYmluZGluZ19yZWZlcmVuY2UiOnsiYXJ0aWZhY3RfZGlnZXN0Ijoic2hhMjU2OjBhYTg0OTUwM2U4M2Y5YmU5NjhjZmM3NzUzZjE0YzY5YTQ5MzUyNDNjZjFmZDQzMjRlY2YwOTRlYmRmOGJlZWIiLCJhcnRpZmFjdF9pZCI6ImFydGlmYWN0LTczNGQzZTdhOTVkMzRkYjVmMzg4MGJiNzY5YTU3N2M4ZGQ3NmIzNDg2OWI4ZGE0MWYwNzY0ODdjNTA2NzZkZWMiLCJhdWRpdF9kaWdlc3QiOiJzaGEyNTY6YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYSIsImF1ZGl0X2lkIjoiYXVkaXQtMSIsImJpbmRpbmdfaWQiOiJiaW5kaW5nLTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJiaW5kaW5nX3JlZmVyZW5jZV9kaWdlc3QiOiJzaGEyNTY6Njg3ODZhMTY2YThmMTIzYjk4Yzg4ZWViMTBjMDU3NTJjYWMzYjYzZTlmZDdjMGM0ZDU2ZjExZmU2NzVjNjE5YSIsImRyaXZlcl9pZGVudGl0eSI6ImdpdGh1Yi1yZXN0LWRyaXZlci12MSIsImV2aWRlbmNlX2RpZ2VzdCI6InNoYTI1NjpkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIiwiZXZpZGVuY2VfaWQiOiJldmlkZW5jZS0xIiwiZ2l0aHViX3N1YmplY3RfaWRlbnRpdHkiOiJzdWJqZWN0LW5vZGUtMSIsIm9wZXJhdGlvbl9zZXRfZGlnZXN0Ijoic2hhMjU2OmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJvcmlnaW5hbF92ZXJpZmllZF9hdCI6IjIwMjYtMDgtMTRUMTE6MzA6MDAuMDAwMDAwWiIsInBsYW5fZGlnZXN0Ijoic2hhMjU2OmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJwcmV2aWV3X2lkIjoicHJldmlldy0xIiwicmVmZXJlbmNlX2NvbnRyYWN0X3ZlcnNpb24iOiJhdHRlc3RhdGlvbi1iaW5kaW5nLXJlZmVyZW5jZS12MSIsInJlZmVyZW5jZV9pZCI6ImJpbmRpbmctcmVmZXJlbmNlLTY1NDAxNDdlNjBhZjI0YjFjY2NhNDEyOTUxMDkwOTllMDJiYzg4MDA3Y2E3YjI5ZjQ4MTFlZmUyMDc4MWJlNjYiLCJyZW1vdGVfYXV0aG9yaXR5Ijoic2hhMjU2OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEiLCJyZW1vdGVfc25hcHNob3RfZGlnZXN0Ijoic2hhMjU2OmNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJyZXBvc2l0b3J5X2lkZW50aXR5Ijoib3duZXIvcmVwb3NpdG9yeSIsInJldmlzaW9uIjoxLCJzZWFsZWRfcHJldmlld19kaWdlc3QiOiJzaGEyNTY6Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYyIsIndvcmtzcGFjZV9pZGVudGl0eSI6IndvcmtzcGFjZS0xIn0sImRvbWFpbiI6ImRlbGl2ZXJ5LXN5c3RlbTphdHRlc3RhdGlvbi1yZXZhbGlkYXRpb24tY29udGV4dDp2MSIsInBheWxvYWRfdmVyc2lvbiI6IjEiLCJ3b3Jrc3BhY2VfaWRlbnRpdHkiOiJ3b3Jrc3BhY2UtMSJ9"
GOLDEN_BARE_SHA256 = "c0721b3bb6f9a33b694c55fca4b465663138c35b173dfb029c1913128c3aa47e"
GOLDEN_DIGEST = "sha256:" + GOLDEN_BARE_SHA256
GOLDEN_RAW_PAYLOAD = json.loads(GOLDEN_RAW_JSON)
GOLDEN_NORMALIZED_PAYLOAD = json.loads(GOLDEN_NORMALIZED_JSON)


def _changed_paths(left: object, right: object, prefix: tuple[object, ...] = ()) -> set[tuple[object, ...]]:
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        paths: set[tuple[object, ...]] = set()
        for key in set(left) | set(right):
            if key not in left or key not in right:
                paths.add(prefix + (key,))
            else:
                paths |= _changed_paths(left[key], right[key], prefix + (key,))
        return paths
    if isinstance(left, list):
        return set() if left == right else {prefix}
    return set() if left == right else {prefix}


def _set_path(payload: dict, path: tuple[object, ...], value: object) -> None:
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value


def _recompute_from_persisted_latest(store, workspace_identity: str, artifact_id: str):
    latest = store.get_latest_revalidation_event(workspace_identity, artifact_id)
    if latest is None:
        raise AssertionError("persisted Event and immutable aggregate are required")
    event = latest.event
    if workspace_identity != event.workspace_identity or artifact_id != event.artifact_id:
        raise AssertionError("bootstrap locator differs from persisted Event locator")
    aggregate = store.get_artifact_aggregate(event.workspace_identity, event.artifact_id)
    if aggregate is None:
        raise AssertionError("persisted immutable aggregate is required")
    if aggregate.artifact.workspace_identity != event.workspace_identity:
        raise AssertionError("workspace locator mismatch")
    if aggregate.artifact.artifact_id != event.artifact_id:
        raise AssertionError("artifact locator mismatch")
    if aggregate.artifact.artifact_digest != event.artifact_digest:
        raise AssertionError("artifact digest locator mismatch")
    if aggregate.binding_reference.binding_reference_digest != event.binding_reference_digest:
        raise AssertionError("binding reference digest locator mismatch")
    payload = _build_restart_revalidation_context_payload(
        (aggregate.artifact, aggregate.binding_reference)
    )
    return latest, aggregate, _derive_restart_revalidation_context_digest(payload)


class CapabilityPolicy:
    def is_supported(self, capability: str) -> bool:
        return capability in {"issues:read", "issues:write"}


class Reader:
    def __init__(self, status: object = RevocationStatus()) -> None:
        self.status = status
        self.calls = 0

    def read_status(self, *args: object) -> object:
        self.calls += 1
        if isinstance(self.status, BaseException):
            raise self.status
        return self.status


class CountingClock:
    def __init__(self, value: object = NOW) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class GateClock:
    def __init__(self, value: datetime, parties: int = 2) -> None:
        self.value = value
        self.calls = 0
        self._gate = threading.Barrier(parties)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            self.calls += 1
        self._gate.wait(timeout=5)
        return self.value


class ScriptedEntropy:
    def __init__(self, values: list[bytes]) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self, size: int) -> bytes:
        self.calls += 1
        value = self.values.pop(0)
        self.assert_size(size, value)
        return value

    @staticmethod
    def assert_size(size: int, value: bytes) -> None:
        if len(value) != size:
            raise AssertionError("test entropy has the wrong size")


class MemoryStore:
    def __init__(self, aggregate: object) -> None:
        self.aggregate = aggregate
        self.append_calls = 0

    def get_artifact_aggregate(self, workspace_identity: str, artifact_id: str) -> object:
        return self.aggregate

    def append_revalidation_event(self, event: object) -> object:
        self.append_calls += 1
        raise AssertionError("append should not be reached")


class RestartTestCase(unittest.TestCase):
    def make_request(self):
        boundary = AttestationRuntimeBoundary(None, None, Reader(), CapabilityPolicy())
        return boundary.create_request(
            repository_identity="owner/repository",
            github_subject_identity="subject-node-1",
            required_capabilities=("issues:read", "issues:write"),
            driver_identity="github-rest-driver-v1",
            remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1",
            revision=1,
            operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64,
            evidence_digest="sha256:" + "d" * 64,
        )

    def make_service(self, *, status: object = RevocationStatus(), entropy: list[bytes] | None = None,
                     now: object = NOW, store=None):
        artifact = artifact_for()
        reference = reference_for(artifact)
        if store is None:
            store = InMemoryAttestationPersistenceStore()
            store.persist_artifact(artifact, reference)
        elif callable(getattr(store, "persist_artifact", None)):
            store.persist_artifact(artifact, reference)
        reader = Reader(status)
        clock = CountingClock(now)
        boundary = RevalidationAttemptBoundary(ScriptedEntropy(entropy or [b"1" * 16]))
        service = RestartRevalidationService(
            store=store,
            revocation_reader=reader,
            attempt_boundary=boundary,
            clock=clock,
        )
        return service, artifact, reference, self.make_request(), reader, clock, boundary, store

    def assert_context_invalid(self, callback) -> None:
        with self.assertRaises(RestartRevalidationError) as raised:
            callback()
        self.assertIs(type(raised.exception), RestartRevalidationError)
        self.assertEqual(raised.exception.code, "attestation_restart_context_invalid")
        self.assertEqual(str(raised.exception), "attestation_restart_context_invalid")


class ApiAndGoldenTests(RestartTestCase):
    def test_error_contract_has_seven_codes_and_no_message_input(self) -> None:
        for code in SERVICE_CODES:
            error = RestartRevalidationError(code=code)
            self.assertEqual(error.code, code)
            self.assertEqual(str(error), code)
            self.assertEqual(repr(error), f"<RestartRevalidationError code={code!r}>")
        self.assertEqual(RestartRevalidationError._SUPPORTED_CODES, frozenset(SERVICE_CODES))
        with self.assertRaises(ValueError):
            RestartRevalidationError(code="not-a-service-code")
        with self.assertRaises(TypeError):
            RestartRevalidationError("attestation_restart_context_invalid", "secret")

    def test_public_result_and_success_contract(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
        result = service.revalidate(
            workspace_identity=artifact.workspace_identity,
            artifact_id=artifact.artifact_id,
            reference=reference,
            request=request,
        )
        self.assertIs(type(result), RestartRevalidationResult)
        self.assertEqual(result.outcome, "Successful")
        self.assertIsNone(result.failure_code)
        self.assertEqual(result.event.event_sequence, 1)
        self.assertEqual(result.event.event.revalidation_context_digest, EXPECTED_CONTEXT_DIGEST)
        self.assertEqual(reader.calls, 1)
        self.assertEqual(clock.calls, 1)

    def test_golden_digest_is_hard_coded_and_protocol_is_independent(self) -> None:
        self.assertEqual(GOLDEN_FIXTURE_ID, "slice_d_revalidation_context_v1_golden_001")
        artifact = artifact_for()
        reference = reference_for(artifact)
        actual_raw = _build_restart_revalidation_context_payload((artifact, reference))
        actual_normalized = normalize(actual_raw)
        actual_canonical = canonical_payload(actual_raw)
        actual_bytes = actual_canonical.encode("utf-8")
        documented_bytes = base64.b64decode(GOLDEN_UTF8_BASE64, validate=True)
        self.assertEqual(actual_raw, GOLDEN_RAW_PAYLOAD)
        self.assertEqual(actual_normalized, GOLDEN_NORMALIZED_PAYLOAD)
        self.assertEqual(actual_canonical, GOLDEN_CANONICAL_JSON)
        self.assertEqual(actual_bytes, documented_bytes)
        self.assertEqual(len(actual_bytes), 3387)
        self.assertEqual(len(documented_bytes), 3387)
        self.assertEqual(base64.b64encode(documented_bytes).decode("ascii"), GOLDEN_UTF8_BASE64)
        self.assertEqual(hashlib.sha256(documented_bytes).hexdigest(), GOLDEN_BARE_SHA256)
        self.assertEqual(digest(GOLDEN_NORMALIZED_PAYLOAD), GOLDEN_DIGEST)
        self.assertEqual(_derive_restart_revalidation_context_digest(actual_raw), GOLDEN_DIGEST)
        self.assertEqual(EXPECTED_CONTEXT_DIGEST, GOLDEN_DIGEST)
        self.assertNotIn("attestation_restart_context_invalid", ATTESTATION_REVALIDATION_FAILURE_CODES)

    def test_caller_cannot_override_context_digest(self) -> None:
        service, artifact, reference, request, *_ = self.make_service()
        with self.assertRaises(TypeError):
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=request, revalidation_context_digest="sha256:" + "0" * 64)


class ValidationTests(RestartTestCase):
    def test_wrong_aggregate_type_is_pre_event(self) -> None:
        store = MemoryStore(object())
        service, artifact, reference, request, reader, clock, boundary, _ = self.make_service(store=store)
        self.assert_context_invalid(lambda: service.revalidate(workspace_identity=artifact.workspace_identity,
                                                                 artifact_id=artifact.artifact_id, reference=reference,
                                                                 request=request))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(clock.calls, 0)
        self.assertEqual(boundary._RevalidationAttemptBoundary__attempt_tombstones, set())

    def test_crosswalk_and_digest_mismatch_are_pre_event(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
        bad = reference_for(artifact, artifact_digest="sha256:" + "e" * 64)
        # Use a direct aggregate store so the existing Store contract is not involved in this Service test.
        aggregate = AttestationArtifactAggregate(artifact, reference)
        object.__setattr__(aggregate, "binding_reference", bad)
        direct = MemoryStore(aggregate)
        service = RestartRevalidationService(store=direct, revocation_reader=reader,
                                             attempt_boundary=boundary, clock=clock)
        self.assert_context_invalid(lambda: service.revalidate(workspace_identity=artifact.workspace_identity,
                                                                 artifact_id=artifact.artifact_id, reference=bad,
                                                                 request=request))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(clock.calls, 0)

    def test_programming_errors_are_not_sanitized(self) -> None:
        for exc in (AttributeError("bug"), KeyError("bug"), TypeError("bug"), ValueError("bug")):
            service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
            with self.subTest(exc=type(exc).__name__), patch(
                "delivery_system.attestation_restart._build_restart_revalidation_context_payload",
                side_effect=exc,
            ):
                with self.assertRaises(type(exc)):
                    service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                                       reference=reference, request=request)
                self.assertEqual(reader.calls, 0)
                self.assertEqual(clock.calls, 0)
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
                self.assertEqual(boundary._RevalidationAttemptBoundary__attempt_tombstones, set())

    def test_digest_helper_error_is_not_sanitized(self) -> None:
        service, artifact, reference, request, *_ = self.make_service()
        with patch("delivery_system.attestation_restart._derive_restart_revalidation_context_digest",
                   side_effect=RuntimeError("implementation bug")):
            with self.assertRaisesRegex(RuntimeError, "implementation bug"):
                service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                                   reference=reference, request=request)


class LongTermEvidenceTests(RestartTestCase):
    def test_request_and_reference_crosswalk_matrix_is_pre_event(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        variations = {
            "repository": {"repository_identity": "other/repository"},
            "subject": {"github_subject_identity": "subject-other"},
            "driver": {"driver_identity": "other-driver"},
            "authority": {"remote_authority": "sha256:" + "f" * 64},
            "preview": {"preview_id": "preview-other"},
            "revision": {"revision": 2},
            "operation": {"operation_set_digest": "sha256:" + "f" * 64},
            "snapshot": {"remote_snapshot_digest": "sha256:" + "f" * 64},
            "evidence": {"evidence_digest": "sha256:" + "f" * 64},
        }
        for name, changes in variations.items():
            with self.subTest(field=name):
                values = {
                    "repository_identity": "owner/repository",
                    "github_subject_identity": "subject-node-1",
                    "required_capabilities": ("issues:read", "issues:write"),
                    "driver_identity": "github-rest-driver-v1",
                    "remote_authority": "sha256:" + "a" * 64,
                    "preview_id": "preview-1",
                    "revision": 1,
                    "operation_set_digest": "sha256:" + "b" * 64,
                    "remote_snapshot_digest": "sha256:" + "c" * 64,
                    "evidence_digest": "sha256:" + "d" * 64,
                }
                values.update(changes)
                request_boundary = AttestationRuntimeBoundary(None, None, Reader(), CapabilityPolicy())
                request = request_boundary.create_request(**values)
                reader = Reader()
                clock = CountingClock()
                attempt = RevalidationAttemptBoundary(ScriptedEntropy([b"z" * 16]))
                store = InMemoryAttestationPersistenceStore()
                store.persist_artifact(artifact, reference)
                service = RestartRevalidationService(store=store, revocation_reader=reader,
                                                     attempt_boundary=attempt, clock=clock)
                with self.assertRaises(RestartRevalidationError) as raised:
                    service.revalidate(workspace_identity=artifact.workspace_identity,
                                       artifact_id=artifact.artifact_id, reference=reference, request=request)
                self.assertEqual(raised.exception.code, "attestation_restart_identity_mismatch")
                self.assertEqual(clock.calls, 0)
                self.assertEqual(reader.calls, 0)
                self.assertEqual(attempt._RevalidationAttemptBoundary__attempt_tombstones, set())
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))

    def test_included_field_mutations_change_digest(self) -> None:
        cases = {
            "domain": lambda p: p.__setitem__("domain", "delivery-system:other:v1"),
            "payload_version": lambda p: p.__setitem__("payload_version", "2"),
            "workspace": lambda p: p.__setitem__("workspace_identity", "workspace-2"),
            "artifact_id": lambda p: p["artifact"].__setitem__("artifact_id", "artifact-mutated"),
            "artifact_digest": lambda p: p["artifact"].__setitem__("artifact_digest", "sha256:" + "f" * 64),
            "attestation_id": lambda p: p["artifact"].__setitem__("attestation_id", "attestation-mutated"),
            "claims_digest": lambda p: p["artifact"].__setitem__("claims_digest", "sha256:" + "f" * 64),
            "created_at": lambda p: p["artifact"].__setitem__("created_at", "2026-08-14T11:32:00.000000Z"),
            "original_verified_at": lambda p: p["artifact"].__setitem__("original_verified_at", "2026-08-14T11:29:00.000000Z"),
            "reference_id": lambda p: p["binding_reference"].__setitem__("reference_id", "reference-mutated"),
            "reference_digest": lambda p: p["binding_reference"].__setitem__("binding_reference_digest", "sha256:" + "f" * 64),
            "reference_revision": lambda p: p["binding_reference"].__setitem__("revision", 2),
            "capabilities": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("granted_capabilities", ["issues:write", "issues:read"]),
            "claims_subject": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("github_subject_identity", "subject-mutated"),
            "claims_repository": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("repository_identity", "other/repository"),
            "claims_driver": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("driver_identity", "other-driver"),
            "claims_authority": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("remote_authority", "sha256:" + "f" * 64),
            "claims_preview": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("preview_id", "preview-mutated"),
            "claims_revision": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("revision", 2),
            "claims_operation": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("operation_set_digest", "sha256:" + "f" * 64),
            "claims_snapshot": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("remote_snapshot_digest", "sha256:" + "f" * 64),
            "claims_evidence": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("evidence_digest", "sha256:" + "f" * 64),
            "claims_issued": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("issued_at", "2026-08-14T10:00:00Z"),
            "claims_expiry": lambda p: p["artifact"]["claims_payload"]["claims"].__setitem__("expires_at", "2026-08-14T14:00:00Z"),
        }
        for name, mutate in cases.items():
            with self.subTest(field=name):
                payload = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                mutate(payload)
                self.assertNotEqual(digest(payload), GOLDEN_DIGEST)

    def test_every_included_json_path_has_unique_digest_sensitivity(self) -> None:
        def set_path(payload, path, value):
            target = payload
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value

        string_cases = [
            (("domain",), "mutated-domain"), (("payload_version",), "2"),
            (("workspace_identity",), "workspace-mutated"),
            (("artifact", "artifact_contract_version"), "offline-attestation-artifact-v2"),
            (("artifact", "artifact_digest"), "sha256:" + "f" * 64),
            (("artifact", "artifact_id"), "artifact-mutated"),
            (("artifact", "attestation_id"), "attestation-mutated"),
            (("artifact", "claims_digest"), "sha256:" + "f" * 64),
            (("artifact", "created_at"), "2026-08-14T11:32:00.000000Z"),
            (("artifact", "original_verified_at"), "2026-08-14T11:29:00.000000Z"),
            (("artifact", "workspace_identity"), "workspace-mutated"),
            (("artifact", "claims_payload", "domain"), "other-claims-domain"),
            (("binding_reference", "reference_contract_version"), "reference-v2"),
            (("binding_reference", "reference_id"), "reference-mutated"),
            (("binding_reference", "workspace_identity"), "workspace-mutated"),
            (("binding_reference", "artifact_id"), "artifact-mutated"),
            (("binding_reference", "artifact_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "binding_id"), "binding-mutated"),
            (("binding_reference", "repository_identity"), "other/repository"),
            (("binding_reference", "github_subject_identity"), "subject-mutated"),
            (("binding_reference", "driver_identity"), "driver-mutated"),
            (("binding_reference", "remote_authority"), "sha256:" + "f" * 64),
            (("binding_reference", "preview_id"), "preview-mutated"),
            (("binding_reference", "plan_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "sealed_preview_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "operation_set_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "remote_snapshot_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "audit_id"), "audit-mutated"),
            (("binding_reference", "audit_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "evidence_id"), "evidence-mutated"),
            (("binding_reference", "evidence_digest"), "sha256:" + "f" * 64),
            (("binding_reference", "original_verified_at"), "2026-08-14T11:29:00.000000Z"),
            (("binding_reference", "binding_reference_digest"), "sha256:" + "f" * 64),
        ]
        claims = ("attestation_version", "issuer_id", "key_id", "signature_algorithm",
                  "credential_class", "credential_instance_id", "github_subject_identity",
                  "repository_identity", "driver_identity", "remote_authority", "preview_id",
                  "operation_set_digest", "remote_snapshot_digest", "evidence_digest", "issued_at",
                  "expires_at", "nonce", "source_verification_digest", "attestation_id")
        for field in claims:
            value = "claims-mutated" if not field.endswith("digest") and field not in {"issued_at", "expires_at"} else (
                "2026-08-14T10:00:00Z" if field in {"issued_at", "expires_at"} else "sha256:" + "f" * 64)
            string_cases.append((("artifact", "claims_payload", "claims", field), value))
        for path, value in string_cases:
            with self.subTest(path=path):
                payload = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                set_path(payload, path, value)
                self.assertNotEqual(digest(payload), GOLDEN_DIGEST)
        for path in (("artifact", "claims_payload", "claims", "granted_capabilities"),):
            with self.subTest(path=path):
                payload = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                set_path(payload, path, ["issues:write", "issues:read"])
                self.assertNotEqual(digest(payload), GOLDEN_DIGEST)
        for path in (("artifact", "claims_payload", "claims", "revision"),
                     ("binding_reference", "revision")):
            with self.subTest(path=path):
                payload = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                set_path(payload, path, 2)
                self.assertNotEqual(digest(payload), GOLDEN_DIGEST)

    def test_every_included_leaf_path_changes_only_itself(self) -> None:
        # This list is an independent, review-owned projection of the frozen payload schema.
        paths = (
            ("domain",), ("payload_version",), ("workspace_identity",),
            ("artifact", "artifact_contract_version"), ("artifact", "artifact_digest"),
            ("artifact", "artifact_id"), ("artifact", "attestation_id"),
            ("artifact", "claims_digest"), ("artifact", "created_at"),
            ("artifact", "original_verified_at"), ("artifact", "workspace_identity"),
            ("artifact", "claims_payload", "domain"),
            ("artifact", "claims_payload", "claims", "attestation_version"),
            ("artifact", "claims_payload", "claims", "issuer_id"),
            ("artifact", "claims_payload", "claims", "key_id"),
            ("artifact", "claims_payload", "claims", "signature_algorithm"),
            ("artifact", "claims_payload", "claims", "credential_class"),
            ("artifact", "claims_payload", "claims", "credential_instance_id"),
            ("artifact", "claims_payload", "claims", "github_subject_identity"),
            ("artifact", "claims_payload", "claims", "repository_identity"),
            ("artifact", "claims_payload", "claims", "granted_capabilities"),
            ("artifact", "claims_payload", "claims", "driver_identity"),
            ("artifact", "claims_payload", "claims", "remote_authority"),
            ("artifact", "claims_payload", "claims", "preview_id"),
            ("artifact", "claims_payload", "claims", "revision"),
            ("artifact", "claims_payload", "claims", "operation_set_digest"),
            ("artifact", "claims_payload", "claims", "remote_snapshot_digest"),
            ("artifact", "claims_payload", "claims", "evidence_digest"),
            ("artifact", "claims_payload", "claims", "issued_at"),
            ("artifact", "claims_payload", "claims", "expires_at"),
            ("artifact", "claims_payload", "claims", "nonce"),
            ("artifact", "claims_payload", "claims", "source_verification_digest"),
            ("artifact", "claims_payload", "claims", "attestation_id"),
            ("binding_reference", "reference_contract_version"),
            ("binding_reference", "reference_id"), ("binding_reference", "workspace_identity"),
            ("binding_reference", "artifact_id"), ("binding_reference", "artifact_digest"),
            ("binding_reference", "binding_id"), ("binding_reference", "repository_identity"),
            ("binding_reference", "github_subject_identity"),
            ("binding_reference", "driver_identity"), ("binding_reference", "remote_authority"),
            ("binding_reference", "preview_id"), ("binding_reference", "revision"),
            ("binding_reference", "plan_digest"), ("binding_reference", "sealed_preview_digest"),
            ("binding_reference", "operation_set_digest"),
            ("binding_reference", "remote_snapshot_digest"), ("binding_reference", "audit_id"),
            ("binding_reference", "audit_digest"), ("binding_reference", "evidence_id"),
            ("binding_reference", "evidence_digest"),
            ("binding_reference", "original_verified_at"),
            ("binding_reference", "binding_reference_digest"),
        )
        for path in paths:
            with self.subTest(path=path):
                before = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                after = copy.deepcopy(GOLDEN_NORMALIZED_PAYLOAD)
                original = before[path[0]] if len(path) == 1 else None
                target = before
                for component in path:
                    target = target[component]
                if isinstance(target, list):
                    replacement = list(reversed(target))
                elif type(target) is int:
                    replacement = target + 1
                else:
                    replacement = "mutated-" + str(target)
                _set_path(after, path, replacement)
                self.assertEqual(_changed_paths(before, after), {path})
                self.assertNotEqual(digest(before), digest(after))

    def test_dynamic_values_are_excluded_from_context_payload(self) -> None:
        for excluded in ("attempt_id", "event_id", "revalidated_at", "event_sequence", "revocation_result"):
            self.assertNotIn(excluded, GOLDEN_CANONICAL_JSON)

    def test_protocol_canonicalizer_vectors_are_not_service_validation(self) -> None:
        raw_collision = {"e\u0301": 1, "é": 2}
        self.assertNotEqual(set(raw_collision), {"é"})
        with self.assertRaisesRegex(ValueError, "^Canonical mapping keys collide after NFC normalization$"):
            canonical_payload(raw_collision)
        with self.assertRaisesRegex(TypeError, "^Unsupported canonical value: object$"):
            canonical_payload({"unsupported": object()})
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "^NaN and infinite floats are not canonical values$"):
                    canonical_payload({"value": value})

    def test_clock_and_validate_use_one_observed_now(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
        observed = []
        original_validate = RevocationStatus.validate

        def validate(status, now):
            observed.append(now)
            return original_validate(status, now)

        with patch.object(RevocationStatus, "validate", validate):
            result = service.revalidate(workspace_identity=artifact.workspace_identity,
                                        artifact_id=artifact.artifact_id, reference=reference, request=request)
        self.assertEqual(clock.calls, 1)
        self.assertEqual(len(observed), 1)
        self.assertIs(observed[0], clock.value)
        self.assertEqual(result.event.event.revalidated_at, clock.value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    def test_revocation_error_codes_are_exact(self) -> None:
        cases = ((None, "attestation_restart_revocation_unknown"),
                 (object(), "attestation_restart_revocation_invalid"),
                 (RuntimeError("reader bug"), "attestation_restart_revocation_unavailable"))
        for status, expected_code in cases:
            with self.subTest(code=expected_code):
                service, artifact, reference, request, reader, clock, boundary, store = self.make_service(status=status)
                with self.assertRaises(RestartRevalidationError) as raised:
                    service.revalidate(workspace_identity=artifact.workspace_identity,
                                       artifact_id=artifact.artifact_id, reference=reference, request=request)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(clock.calls, 1)
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))

    def test_programming_digest_error_has_no_downstream_side_effects(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
        with patch("delivery_system.attestation_restart._derive_restart_revalidation_context_digest",
                   side_effect=RuntimeError("digest bug")):
            with self.assertRaisesRegex(RuntimeError, "digest bug"):
                service.revalidate(workspace_identity=artifact.workspace_identity,
                                   artifact_id=artifact.artifact_id, reference=reference, request=request)
        self.assertEqual(reader.calls, 0)
        self.assertEqual(clock.calls, 0)
        self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
        self.assertEqual(boundary._RevalidationAttemptBoundary__attempt_tombstones, set())

    def test_sequential_shared_boundary_collision_has_no_sequence_gap(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        boundary = RevalidationAttemptBoundary(ScriptedEntropy([b"x" * 16, b"x" * 16, b"y" * 16]))
        service = RestartRevalidationService(store=store, revocation_reader=Reader(),
                                             attempt_boundary=boundary, clock=CountingClock())
        request = self.make_request()
        service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                           reference=reference, request=request)
        with self.assertRaises(PersistenceContractError) as raised:
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=request)
        self.assertEqual(raised.exception.code, "attestation_attempt_id_collision")
        service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                           reference=reference, request=request)
        self.assertEqual(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id).event_sequence, 2)

    def test_concurrent_repeated_entropy_has_one_collision(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        class BarrierEntropy:
            def __init__(self):
                self.barrier = threading.Barrier(2)
                self.calls = 0
                self.lock = threading.Lock()

            def __call__(self, size: int) -> bytes:
                with self.lock:
                    self.calls += 1
                self.barrier.wait(timeout=5)
                return b"q" * size

        entropy = BarrierEntropy()
        boundary = RevalidationAttemptBoundary(entropy)
        services = [RestartRevalidationService(store=store, revocation_reader=Reader(),
                                                attempt_boundary=boundary, clock=CountingClock()) for _ in range(2)]
        request = self.make_request()
        def invoke(service):
            return service.revalidate(workspace_identity=artifact.workspace_identity,
                                      artifact_id=artifact.artifact_id, reference=reference, request=request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(invoke, service) for service in services]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(("success", future.result(timeout=5)))
                except PersistenceContractError as error:
                    outcomes.append((error.code, None))
        self.assertEqual(sorted(item[0] for item in outcomes), ["attestation_attempt_id_collision", "success"])
        self.assertEqual(entropy.calls, 2)
        latest = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
        self.assertEqual(latest.event_sequence, 1)

    def test_concurrent_distinct_entropy_is_contiguous(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)

        class DistinctBarrierEntropy:
            def __init__(self):
                self.barrier = threading.Barrier(2)
                self.values = iter((b"a" * 16, b"b" * 16))
                self.calls = 0
                self.lock = threading.Lock()

            def __call__(self, size: int) -> bytes:
                with self.lock:
                    self.calls += 1
                    value = next(self.values)
                self.barrier.wait(timeout=5)
                return value

        entropy = DistinctBarrierEntropy()
        boundary = RevalidationAttemptBoundary(entropy)
        services = [RestartRevalidationService(store=store, revocation_reader=Reader(),
                                                attempt_boundary=boundary, clock=CountingClock()) for _ in range(2)]
        artifact_id = artifact.artifact_id
        request = self.make_request()

        def invoke(service):
            return service.revalidate(workspace_identity=artifact.workspace_identity,
                                      artifact_id=artifact_id, reference=reference, request=request)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(invoke, service) for service in services]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual([result.outcome for result in results], ["Successful", "Successful"])
        self.assertEqual(entropy.calls, 2)
        latest = store.get_latest_revalidation_event(artifact.workspace_identity, artifact_id)
        self.assertEqual(latest.event_sequence, 2)

    def test_append_failure_is_not_context_invalid_or_retried(self) -> None:
        class FailingAppendStore:
            def __init__(self, aggregate):
                self.aggregate = aggregate
                self.calls = 0

            def get_artifact_aggregate(self, workspace_identity, artifact_id):
                return self.aggregate

            def append_revalidation_event(self, event):
                self.calls += 1
                raise StoreContractError("attestation_persistence_sqlite_busy")

        artifact = artifact_for()
        reference = reference_for(artifact)
        store = FailingAppendStore(AttestationArtifactAggregate(artifact, reference))
        service = RestartRevalidationService(store=store, revocation_reader=Reader(),
                                             attempt_boundary=RevalidationAttemptBoundary(), clock=CountingClock())
        with self.assertRaises(StoreContractError) as raised:
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=self.make_request())
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_busy")
        self.assertEqual(store.calls, 1)


class OutcomeTests(RestartTestCase):
    def test_expired_and_revoked_are_existing_event_codes(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service(
            now=datetime(2026, 8, 14, 14, tzinfo=timezone.utc))
        result = service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                                    reference=reference, request=request)
        self.assertEqual(result.failure_code, "attestation_revalidation_expired")
        self.assertEqual(reader.calls, 0)
        self.assertEqual(result.event.event_sequence, 1)

        service, artifact, reference, request, reader, clock, boundary, store = self.make_service(
            status=RevocationStatus(attestation_revoked=True, revoked_at="2026-08-14T11:30:00Z", reason="revoked"))
        result = service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                                    reference=reference, request=request)
        self.assertEqual(result.failure_code, "attestation_revalidation_revoked")
        self.assertEqual(result.event.event_sequence, 1)

    def test_revocation_no_event_paths_are_side_effect_free(self) -> None:
        for status in (None, object(), RuntimeError("reader")):
            with self.subTest(status=type(status).__name__):
                service, artifact, reference, request, reader, clock, boundary, store = self.make_service(status=status)
                with self.assertRaises(RestartRevalidationError):
                    service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                                       reference=reference, request=request)
                self.assertEqual(clock.calls, 1)
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))

    def test_repeated_entropy_is_collision_without_downstream_calls(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        entropy = ScriptedEntropy([b"2" * 16, b"2" * 16])
        boundary = RevalidationAttemptBoundary(entropy)
        reader = Reader()
        clock = CountingClock()
        service = RestartRevalidationService(store=store, revocation_reader=reader, attempt_boundary=boundary, clock=clock)
        request = self.make_request()
        service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                           reference=reference, request=request)
        with self.assertRaises(PersistenceContractError) as raised:
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=request)
        self.assertEqual(raised.exception.code, "attestation_attempt_id_collision")
        self.assertEqual(entropy.calls, 2)
        self.assertEqual(clock.calls, 1)
        self.assertEqual(reader.calls, 1)
        self.assertEqual(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id).event_sequence, 1)

    def test_clock_and_reader_failures_have_stable_codes(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service(now=RuntimeError("secret"))
        with self.assertRaisesRegex(RestartRevalidationError, "attestation_restart_clock_invalid"):
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=request)
        self.assertEqual(reader.calls, 0)
        self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))

    def test_revocation_validation_version_failure_is_no_event(self) -> None:
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service(
            status=RevocationStatus(version="2"))
        with self.assertRaises(RestartRevalidationError) as raised:
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=request)
        self.assertEqual(raised.exception.code, "attestation_restart_revocation_invalid")
        self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))

    def test_two_services_share_attempt_boundary_without_retry(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        request = self.make_request()
        shared_boundary = RevalidationAttemptBoundary(ScriptedEntropy([b"3" * 16, b"4" * 16]))
        gate = GateClock(NOW)
        services = [
            RestartRevalidationService(store=store, revocation_reader=Reader(),
                                       attempt_boundary=shared_boundary, clock=gate),
            RestartRevalidationService(store=store, revocation_reader=Reader(),
                                       attempt_boundary=shared_boundary, clock=gate),
        ]
        def invoke(service: RestartRevalidationService) -> RestartRevalidationResult:
            return service.revalidate(workspace_identity=artifact.workspace_identity,
                                      artifact_id=artifact.artifact_id, reference=reference, request=request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(invoke, service) for service in services]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual([result.outcome for result in results], ["Successful", "Successful"])
        self.assertEqual(gate.calls, 2)
        latest = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
        self.assertEqual(latest.event_sequence, 2)

    def test_store_errors_keep_store_ownership(self) -> None:
        class FailingStore:
            def get_artifact_aggregate(self, workspace_identity: str, artifact_id: str) -> object:
                raise StoreContractError("attestation_persistence_sqlite_busy")
        artifact = artifact_for()
        reference = reference_for(artifact)
        service = RestartRevalidationService(store=FailingStore(), revocation_reader=Reader(),
                                             attempt_boundary=RevalidationAttemptBoundary(), clock=CountingClock())
        with self.assertRaises(StoreContractError) as raised:
            service.revalidate(workspace_identity=artifact.workspace_identity, artifact_id=artifact.artifact_id,
                               reference=reference, request=self.make_request())
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_busy")


class AggregateValidationMatrixTests(RestartTestCase):
    def test_missing_component_and_invalid_payload_type_are_service_owned(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        request = self.make_request()
        cases = {}
        missing = object.__new__(AttestationArtifactAggregate)
        object.__setattr__(missing, "artifact", artifact)
        cases["missing-binding-reference"] = missing
        invalid = AttestationArtifactAggregate(artifact, reference)
        object.__setattr__(invalid.artifact, "claims_payload", object())
        cases["invalid-payload-type"] = invalid
        for name, aggregate in cases.items():
            with self.subTest(case=name):
                store = MemoryStore(aggregate)
                entropy = ScriptedEntropy([b"m" * 16])
                boundary = RevalidationAttemptBoundary(entropy)
                reader = Reader()
                clock = CountingClock()
                service = RestartRevalidationService(store=store, revocation_reader=reader,
                                                     attempt_boundary=boundary, clock=clock)
                self.assert_context_invalid(
                    lambda: service.revalidate(workspace_identity="workspace-1",
                                               artifact_id=artifact.artifact_id,
                                               reference=reference, request=request)
                )
                self.assertEqual(entropy.calls, 0)
                self.assertEqual(clock.calls, 0)
                self.assertEqual(reader.calls, 0)
                self.assertEqual(store.append_calls, 0)
                self.assertEqual(boundary._RevalidationAttemptBoundary__attempt_tombstones, set())

    def test_explicit_context_corruption_is_pre_event(self) -> None:
        def corrupt(component, field, value):
            object.__setattr__(component, field, value)

        cases = {
            "missing-artifact": lambda artifact, reference: corrupt(artifact, "artifact_id", ""),
            "workspace": lambda artifact, reference: corrupt(artifact, "workspace_identity", "workspace-other"),
            "artifact-id": lambda artifact, reference: corrupt(artifact, "artifact_id", "artifact-other"),
            "artifact-digest": lambda artifact, reference: corrupt(artifact, "artifact_digest", "sha256:" + "f" * 64),
            "claims-id": lambda artifact, reference: corrupt(artifact.claims_payload, "attestation_id", "attestation-other"),
            "claims-digest": lambda artifact, reference: corrupt(artifact, "claims_digest", "sha256:" + "f" * 64),
            "contract-version": lambda artifact, reference: corrupt(artifact, "artifact_contract_version", "artifact-v2"),
            "revision": lambda artifact, reference: corrupt(artifact.claims_payload, "revision", 0),
            "required-string": lambda artifact, reference: corrupt(artifact.claims_payload, "issuer_id", ""),
            "capability-type": lambda artifact, reference: corrupt(artifact.claims_payload, "granted_capabilities", {"issues:read": True}),
            "capability-empty": lambda artifact, reference: corrupt(artifact.claims_payload, "granted_capabilities", ()),
            "capability-duplicate": lambda artifact, reference: corrupt(artifact.claims_payload, "granted_capabilities", ("issues:read", "issues:read")),
            "capability-order": lambda artifact, reference: corrupt(artifact.claims_payload, "granted_capabilities", ("issues:write", "issues:read")),
            "timestamp": lambda artifact, reference: corrupt(artifact, "created_at", "not-a-timestamp"),
        }
        for name, mutation in cases.items():
            with self.subTest(case=name):
                artifact = artifact_for()
                reference = reference_for(artifact)
                original_artifact_id = artifact.artifact_id
                mutation(artifact, reference)
                aggregate = object.__new__(AttestationArtifactAggregate)
                object.__setattr__(aggregate, "artifact", artifact)
                object.__setattr__(aggregate, "binding_reference", reference)
                store = MemoryStore(aggregate)
                reader = Reader()
                clock = CountingClock()
                boundary = RevalidationAttemptBoundary(ScriptedEntropy([b"v" * 16]))
                service = RestartRevalidationService(store=store, revocation_reader=reader,
                                                     attempt_boundary=boundary, clock=clock)
                with self.assertRaises(RestartRevalidationError) as raised:
                    service.revalidate(workspace_identity="workspace-1", artifact_id=original_artifact_id,
                                       reference=reference, request=self.make_request())
                self.assertEqual(raised.exception.code, "attestation_restart_context_invalid")
                self.assertEqual(str(raised.exception), "attestation_restart_context_invalid")
                self.assertNotIn("artifact", repr(raised.exception))
                self.assertEqual(clock.calls, 0)
                self.assertEqual(reader.calls, 0)
                self.assertEqual(store.append_calls, 0)
                self.assertEqual(boundary._RevalidationAttemptBoundary__attempt_tombstones, set())

    def test_canonicalizer_vectors_are_not_persisted_aggregate_contract(self) -> None:
        self.assertFalse(restart_module._json_compatible({"e\u0301": 1, "é": 2}))
        self.assertFalse(restart_module._json_compatible({"unsupported": object()}))
        self.assertFalse(restart_module._json_compatible(float("nan")))
        self.assertFalse(restart_module._json_compatible(float("inf")))

    def test_revocation_timestamp_and_validation_failure_matrix(self) -> None:
        statuses = {}
        invalid_timestamp = object.__new__(RevocationStatus)
        object.__setattr__(invalid_timestamp, "version", "1")
        object.__setattr__(invalid_timestamp, "attestation_revoked", True)
        object.__setattr__(invalid_timestamp, "credential_instance_revoked", False)
        object.__setattr__(invalid_timestamp, "revoked_at", "invalid-timestamp")
        object.__setattr__(invalid_timestamp, "reason", "reason")
        future = object.__new__(RevocationStatus)
        object.__setattr__(future, "version", "1")
        object.__setattr__(future, "attestation_revoked", True)
        object.__setattr__(future, "credential_instance_revoked", False)
        object.__setattr__(future, "revoked_at", "2026-08-14T13:00:00Z")
        object.__setattr__(future, "reason", "reason")
        statuses["invalid-timestamp"] = invalid_timestamp
        statuses["future-timestamp"] = future
        for name, status in statuses.items():
            with self.subTest(case=name):
                service, artifact, reference, request, reader, clock, boundary, store = self.make_service(status=status)
                observed = []
                original_validate = RevocationStatus.validate

                def observe(current, now):
                    observed.append(now)
                    return original_validate(current, now)

                with patch.object(RevocationStatus, "validate", observe):
                    with self.assertRaises(RestartRevalidationError) as raised:
                        service.revalidate(workspace_identity=artifact.workspace_identity,
                                           artifact_id=artifact.artifact_id, reference=reference, request=request)
                self.assertEqual(raised.exception.code, "attestation_restart_revocation_invalid")
                self.assertEqual(clock.calls, 1)
                self.assertEqual(reader.calls, 1)
                self.assertEqual(len(observed), 1)
                self.assertIs(observed[0], clock.value)
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
        service, artifact, reference, request, reader, clock, boundary, store = self.make_service()
        observed = []

        def reject(current, now):
            observed.append(now)
            raise AttestationContractError("revocation_invalid")

        with patch.object(RevocationStatus, "validate", reject):
            with self.assertRaises(RestartRevalidationError) as raised:
                service.revalidate(workspace_identity=artifact.workspace_identity,
                                   artifact_id=artifact.artifact_id, reference=reference, request=request)
        self.assertEqual(raised.exception.code, "attestation_restart_revocation_invalid")
        self.assertEqual(clock.calls, 1)
        self.assertEqual(reader.calls, 1)
        self.assertEqual(observed, [clock.value])
        self.assertIs(observed[0], clock.value)
        self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))


class BackendParityTests(RestartTestCase):
    def test_sqlite_and_inmemory_success_projection_parity(self) -> None:
        memory = self.make_service()
        memory_result = memory[0].revalidate(workspace_identity=memory[1].workspace_identity,
                                             artifact_id=memory[1].artifact_id, reference=memory[2], request=memory[3])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite"
            sqlite_store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                service, artifact, reference, request, *_ = self.make_service(store=sqlite_store)
                sqlite_result = service.revalidate(workspace_identity=artifact.workspace_identity,
                                                   artifact_id=artifact.artifact_id, reference=reference, request=request)
                self.assertEqual(sqlite_result.outcome, memory_result.outcome)
                self.assertEqual(sqlite_result.event.event.event_payload_digest,
                                 memory_result.event.event.event_payload_digest)
                self.assertEqual(sqlite_result.event.event.revalidation_context_digest,
                                 memory_result.event.event.revalidation_context_digest)
            finally:
                sqlite_store.close()
            self.assertFalse((Path(directory) / "restart.sqlite-wal").exists())
            self.assertFalse((Path(directory) / "restart.sqlite-shm").exists())

    def test_sqlite_close_reopen_corruption_and_restart_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite"
            artifact = artifact_for()
            reference = reference_for(artifact)
            first = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                first.persist_artifact(artifact, reference)
                boundary = RevalidationAttemptBoundary(ScriptedEntropy([b"r" * 16, b"s" * 16]))
                service = RestartRevalidationService(store=first, revocation_reader=Reader(),
                                                     attempt_boundary=boundary, clock=CountingClock())
                result = service.revalidate(workspace_identity=artifact.workspace_identity,
                                             artifact_id=artifact.artifact_id, reference=reference,
                                             request=self.make_request())
                first_digest = result.event.event.revalidation_context_digest
            finally:
                first.close()
            reopened = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                latest = reopened.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
                self.assertEqual(latest.event_sequence, 1)
                self.assertEqual(latest.event.revalidation_context_digest, first_digest)
                restarted = RestartRevalidationService(store=reopened, revocation_reader=Reader(),
                                                       attempt_boundary=boundary, clock=CountingClock())
                second = restarted.revalidate(workspace_identity=artifact.workspace_identity,
                                               artifact_id=artifact.artifact_id, reference=reference,
                                               request=self.make_request())
                self.assertEqual(second.event.event_sequence, 2)
                self.assertEqual(second.event.event.revalidation_context_digest, first_digest)
                reopened._connection.execute(
                    "UPDATE attestation_artifacts SET canonical_json=? WHERE workspace_identity=? AND artifact_id=?",
                    ("{corrupt", artifact.workspace_identity, artifact.artifact_id),
                )
                reopened._connection.commit()
            finally:
                reopened.close()
            corrupt_store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                reader = Reader()
                clock = CountingClock()
                boundary_after_corruption = RevalidationAttemptBoundary(ScriptedEntropy([b"t" * 16]))
                corrupt_service = RestartRevalidationService(
                    store=corrupt_store, revocation_reader=reader,
                    attempt_boundary=boundary_after_corruption, clock=clock,
                )
                with self.assertRaises(StoreContractError) as raised:
                    corrupt_service.revalidate(workspace_identity=artifact.workspace_identity,
                                               artifact_id=artifact.artifact_id, reference=reference,
                                               request=self.make_request())
                self.assertEqual(raised.exception.code, "attestation_artifact_aggregate_corrupt")
                self.assertEqual(clock.calls, 0)
                self.assertEqual(reader.calls, 0)
                self.assertEqual(boundary_after_corruption._RevalidationAttemptBoundary__attempt_tombstones, set())
            finally:
                corrupt_store.close()
            self.assertFalse((path.parent / "restart.sqlite-wal").exists())
            self.assertFalse((path.parent / "restart.sqlite-shm").exists())

    def test_post_event_recomputation_uses_persisted_event_and_immutable_aggregate(self) -> None:
        for backend in ("memory", "sqlite"):
            with self.subTest(backend=backend):
                if backend == "memory":
                    service, artifact, reference, request, *_ = self.make_service()
                    service.revalidate(workspace_identity=artifact.workspace_identity,
                                       artifact_id=artifact.artifact_id,
                                       reference=reference, request=request)
                    latest, aggregate, recomputed = _recompute_from_persisted_latest(
                        service._RestartRevalidationService__store,
                        artifact.workspace_identity, artifact.artifact_id,
                    )
                    self.assertEqual(artifact.workspace_identity, latest.event.workspace_identity)
                    self.assertEqual(artifact.artifact_id, latest.event.artifact_id)
                    self.assertEqual(aggregate.artifact.workspace_identity, latest.event.workspace_identity)
                    self.assertEqual(latest.event.revalidation_context_digest, recomputed)
                    self.assertEqual(aggregate.artifact.artifact_id, latest.event.artifact_id)
                    self.assertEqual(aggregate.artifact.artifact_digest, latest.event.artifact_digest)
                    self.assertEqual(
                        aggregate.binding_reference.binding_reference_digest,
                        latest.event.binding_reference_digest,
                    )
                    continue
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "recompute.sqlite"
                    store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
                    try:
                        service, artifact, reference, request, *_ = self.make_service(store=store)
                        service.revalidate(workspace_identity=artifact.workspace_identity,
                                           artifact_id=artifact.artifact_id,
                                           reference=reference, request=request)
                        latest, aggregate, recomputed = _recompute_from_persisted_latest(
                            store, artifact.workspace_identity, artifact.artifact_id
                        )
                        self.assertEqual(artifact.workspace_identity, latest.event.workspace_identity)
                        self.assertEqual(artifact.artifact_id, latest.event.artifact_id)
                        self.assertEqual(aggregate.artifact.workspace_identity, latest.event.workspace_identity)
                        self.assertEqual(latest.event.revalidation_context_digest, recomputed)
                        self.assertEqual(aggregate.artifact.artifact_id, latest.event.artifact_id)
                        self.assertEqual(latest.event.artifact_digest, aggregate.artifact.artifact_digest)
                        self.assertEqual(
                            latest.event.binding_reference_digest,
                            aggregate.binding_reference.binding_reference_digest,
                        )
                    finally:
                        store.close()
                    reopened = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
                    try:
                        latest, aggregate, recomputed = _recompute_from_persisted_latest(
                            reopened, artifact.workspace_identity, artifact.artifact_id
                        )
                        self.assertEqual(artifact.workspace_identity, latest.event.workspace_identity)
                        self.assertEqual(artifact.artifact_id, latest.event.artifact_id)
                        self.assertEqual(aggregate.artifact.artifact_digest, latest.event.artifact_digest)
                        self.assertEqual(
                            aggregate.binding_reference.binding_reference_digest,
                            latest.event.binding_reference_digest,
                        )
                        self.assertEqual(latest.event.revalidation_context_digest, recomputed)
                        self.assertEqual(latest.event_sequence, 1)
                    finally:
                        reopened.close()
                    self.assertFalse(path.with_name(path.name + "-wal").exists())
                    self.assertFalse(path.with_name(path.name + "-shm").exists())
                    self.assertFalse(path.with_name(path.name + "-journal").exists())

    def test_tampered_persisted_event_digest_is_not_recomputed_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered-event.sqlite"
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                service, artifact, reference, request, *_ = self.make_service(store=store)
                service.revalidate(workspace_identity=artifact.workspace_identity,
                                   artifact_id=artifact.artifact_id,
                                   reference=reference, request=request)
                persisted = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
                tampered = AttestationRevalidationEvent.create(
                    workspace_identity=persisted.event.workspace_identity,
                    artifact_id=persisted.event.artifact_id,
                    artifact_digest=persisted.event.artifact_digest,
                    revalidation_attempt_id=persisted.event.revalidation_attempt_id,
                    revalidation_context_digest="sha256:" + "0" * 64,
                    binding_reference_digest=persisted.event.binding_reference_digest,
                    outcome=persisted.event.outcome,
                    revalidated_at=persisted.event.revalidated_at,
                    failure_code=persisted.event.failure_code,
                    result_digest=persisted.event.result_digest,
                )
                payload = tampered.to_payload()
                store._connection.execute(
                    "UPDATE attestation_revalidation_events SET revalidation_context_digest=?, event_payload_digest=?, canonical_json=? WHERE workspace_identity=? AND event_id=?",
                    (tampered.revalidation_context_digest, tampered.event_payload_digest,
                     json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                     artifact.workspace_identity, persisted.event.event_id),
                )
                store._connection.commit()
                latest, _, recomputed = _recompute_from_persisted_latest(
                    store, artifact.workspace_identity, artifact.artifact_id
                )
                self.assertEqual(latest.event.revalidation_context_digest, "sha256:" + "0" * 64)
                self.assertNotEqual(latest.event.revalidation_context_digest, recomputed)
            finally:
                store.close()
            self.assertFalse(path.with_name(path.name + "-wal").exists())
            self.assertFalse(path.with_name(path.name + "-shm").exists())
            self.assertFalse(path.with_name(path.name + "-journal").exists())

    def test_event_locator_digest_tampering_cannot_use_external_fixture_values(self) -> None:
        for field in ("artifact_digest", "binding_reference_digest"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / (field + ".sqlite")
                store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
                try:
                    service, artifact, reference, request, *_ = self.make_service(store=store)
                    service.revalidate(workspace_identity=artifact.workspace_identity,
                                       artifact_id=artifact.artifact_id,
                                       reference=reference, request=request)
                    persisted = store.get_latest_revalidation_event(
                        artifact.workspace_identity, artifact.artifact_id
                    )
                    values = {
                        "artifact_digest": persisted.event.artifact_digest,
                        "binding_reference_digest": persisted.event.binding_reference_digest,
                    }
                    values[field] = "sha256:" + "f" * 64
                    tampered = AttestationRevalidationEvent.create(
                        workspace_identity=persisted.event.workspace_identity,
                        artifact_id=persisted.event.artifact_id,
                        artifact_digest=values["artifact_digest"],
                        revalidation_attempt_id=persisted.event.revalidation_attempt_id,
                        revalidation_context_digest=persisted.event.revalidation_context_digest,
                        binding_reference_digest=values["binding_reference_digest"],
                        outcome=persisted.event.outcome,
                        revalidated_at=persisted.event.revalidated_at,
                        failure_code=persisted.event.failure_code,
                        result_digest=persisted.event.result_digest,
                    )
                    payload = tampered.to_payload()
                    store._connection.execute("PRAGMA foreign_keys=OFF")
                    store._connection.execute(
                        "UPDATE attestation_revalidation_events SET artifact_digest=?, binding_reference_digest=?, event_payload_digest=?, canonical_json=? WHERE workspace_identity=? AND event_id=?",
                        (tampered.artifact_digest, tampered.binding_reference_digest,
                         tampered.event_payload_digest,
                         json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                         artifact.workspace_identity, persisted.event.event_id),
                    )
                    store._connection.commit()
                    store._connection.execute("PRAGMA foreign_keys=ON")
                    with self.assertRaises(StoreContractError) as raised:
                        _recompute_from_persisted_latest(
                            store, artifact.workspace_identity, artifact.artifact_id
                        )
                    self.assertEqual(raised.exception.code, "attestation_revalidation_event_corrupt")
                finally:
                    store.close()
                self.assertFalse(path.with_name(path.name + "-wal").exists())
                self.assertFalse(path.with_name(path.name + "-shm").exists())
                self.assertFalse(path.with_name(path.name + "-journal").exists())

    def test_sqlite_commit_unknown_is_store_owned_and_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commit-unknown.sqlite"
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                artifact = artifact_for()
                reference = reference_for(artifact)
                store.persist_artifact(artifact, reference)
                entropy = ScriptedEntropy([b"z" * 16])
                boundary = RevalidationAttemptBoundary(entropy)
                clock = CountingClock()
                service = RestartRevalidationService(store=store, revocation_reader=Reader(),
                                                     attempt_boundary=boundary, clock=clock)
                real_connection = store._connection

                class CommitUnknownConnection:
                    def __init__(self, connection):
                        self.connection = connection
                        self.commits = 0

                    def commit(self):
                        self.commits += 1
                        if self.commits == 1:
                            return self.connection.commit()
                        raise sqlite3.OperationalError("commit outcome unknown")

                    def close(self):
                        return self.connection.close()

                    def __getattr__(self, name):
                        return getattr(self.connection, name)

                store._connection = CommitUnknownConnection(real_connection)
                with patch.object(store, "append_revalidation_event",
                                  wraps=store.append_revalidation_event) as append:
                    with self.assertRaises(StoreContractError) as raised:
                        service.revalidate(workspace_identity=artifact.workspace_identity,
                                           artifact_id=artifact.artifact_id,
                                           reference=reference, request=self.make_request())
                self.assertEqual(raised.exception.code, "attestation_persistence_commit_outcome_unknown")
                self.assertEqual(append.call_count, 1)
                self.assertEqual(entropy.calls, 1)
                self.assertEqual(clock.calls, 1)
                self.assertEqual(store._state, SQLiteAttestationPersistenceStore.CLOSED)
            finally:
                store.close()
            reopened = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                durable = reopened.get_latest_revalidation_event("workspace-1", artifact.artifact_id)
                if durable is not None:
                    self.assertEqual(durable.event_sequence, 1)
                    self.assertEqual(durable.event.artifact_id, artifact.artifact_id)
            finally:
                reopened.close()
            self.assertFalse(path.with_name(path.name + "-wal").exists())
            self.assertFalse(path.with_name(path.name + "-shm").exists())
            self.assertFalse(path.with_name(path.name + "-journal").exists())

    def test_commit_unknown_store_error_is_not_retried_or_remapped(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        service = RestartRevalidationService(store=store, revocation_reader=Reader(),
                                             attempt_boundary=RevalidationAttemptBoundary(), clock=CountingClock())
        with patch.object(store, "append_revalidation_event",
                          side_effect=StoreContractError("attestation_persistence_commit_outcome_unknown")) as append:
            with self.assertRaises(StoreContractError) as raised:
                service.revalidate(workspace_identity=artifact.workspace_identity,
                                   artifact_id=artifact.artifact_id, reference=reference,
                                   request=self.make_request())
        self.assertEqual(raised.exception.code, "attestation_persistence_commit_outcome_unknown")
        self.assertEqual(append.call_count, 1)

    def test_sqlite_append_rollback_preserves_next_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rollback.sqlite"
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                artifact = artifact_for()
                reference = reference_for(artifact)
                store.persist_artifact(artifact, reference)
                boundary = RevalidationAttemptBoundary(ScriptedEntropy([b"u" * 16, b"v" * 16]))
                service = RestartRevalidationService(store=store, revocation_reader=Reader(),
                                                     attempt_boundary=boundary, clock=CountingClock())
                with patch.object(store, "_commit_locked", side_effect=sqlite3.OperationalError("busy")):
                    with self.assertRaises(StoreContractError) as raised:
                        service.revalidate(workspace_identity=artifact.workspace_identity,
                                           artifact_id=artifact.artifact_id, reference=reference,
                                           request=self.make_request())
                self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_busy")
                self.assertIsNone(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
                successful = service.revalidate(workspace_identity=artifact.workspace_identity,
                                                 artifact_id=artifact.artifact_id, reference=reference,
                                                 request=self.make_request())
                self.assertEqual(successful.event.event_sequence, 1)
            finally:
                store.close()
            reopened = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            try:
                durable = reopened.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
                self.assertIsNotNone(durable)
                self.assertEqual(durable.event_sequence, 1)
            finally:
                reopened.close()
            self.assertFalse((path.parent / "rollback.sqlite-wal").exists())
            self.assertFalse((path.parent / "rollback.sqlite-shm").exists())
            self.assertFalse((path.parent / "rollback.sqlite-journal").exists())


if __name__ == "__main__":
    unittest.main()
