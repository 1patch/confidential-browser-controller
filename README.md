# Confidential browser controller

Go controller for independently isolated browser workers, with a one-use attested
bootstrap, owner-bound encrypted S3 state and optional scoped AWS STS issuance.
This export contains no application/Pi code, runtime credentials or private
repository history. The runtime image contains no Node or Chromium. Browser
source dependencies are present for the common protocol and fixture tests;
the controller entrypoint cannot execute agent JavaScript or start local Chromium.

The measured startup drops UID/GID, groups, capabilities and inherited variables
before any runtime credential exists. Private no-swap RAM and an independent
inline measured root public key are required. The corresponding root private key
stays with the operator. Runtime storage location arrives only after exact
release attestation, through one signed controller-bootstrap request. No tenant
is prepared at bootstrap. Failed starts retain the claim and never reset.

Enrollment and the controller identity must already exist in encrypted S3.
Each owner needs a distinct IAM role/bucket; the controller has its own role,
bucket and encryption key. Worker identity is initialized only after a durable
preparation record. Bootstrap, storage renewal and drain keep their exact
commitments, inspect uncertain replies read-only and never replay browser actions.
Automatic storage renewal preserves owner identity, conditional-write versions,
idle timestamps and quarantine. Short-lived authority must itself be renewed by
the operator; a fresh controller boot requires a usable bootstrap storage lease.

The controller is a trusted authority: compromise can affect every enrolled
owner. Agents receive neither its signing keys, IAM authority, storage keys nor
administrative API. Operators must verify actual IAM boundaries and retention,
publish immutable measured releases, and keep one controller writer.

The workflows test the exact root-drop launcher before publishing an image.
After pinning the verified image and public root key, dispatch
`tinfoil-release.yml` with a new version on the default branch. It creates that
immutable tag and dispatches `tinfoil-release-publish.yml` on the exact tag.
Existing tags and uncertain requests fail without retries. Wait for the publish
workflow's measurement and attestation before using the new release.
`tinfoil-config.yml.example` contains invalid placeholders. Publication is not
hardware deployment: independently verify the pinned release, attested boot,
storage, browser lifecycle and scale before activation. The 100-owner tests use
fixtures and do not prove 100 live browsers. Storage encryption does not prevent
an S3 administrator from rolling back authentic ciphertext.

The optional `agentRuntime: true` enrollment selects a separately pinned Pi worker
and requires an inference credential in every encrypted owner policy. Default
enrollment remains browser-only and rejects inference keys. This controller
image contains no Pi runtime or application adapter. Runtime selection is part
of the immutable enrollment and cannot change during a worker restart.
