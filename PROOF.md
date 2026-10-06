# Controller proof — October 5, 2026

The minimal controller image is public and anonymously pullable:

```
ghcr.io/1patch/confidential-browser-controller@sha256:c659cc4c35fc8772871c1eeffa176f2b0479aa4d7630b4f5b38bcefa83f4135a
```

Image source: `61664338de33f4c37f78e1c8e427d31b522aa4d8`.
The [image acceptance workflow](https://github.com/1patch/confidential-browser-controller/actions/runs/37391401600)
passed tests through the exact privilege-dropping launcher before publication.

[Release controller-proof-20261005-1](https://github.com/1patch/confidential-browser-controller/releases/tag/controller-proof-20261005-1)
has immutable configuration source `33b1605a762699fff7cef4940400a98266799d72`.
Its [measurement workflow](https://github.com/1patch/confidential-browser-controller/actions/runs/37392011082)
produced manifest digest:

```
sha256:f933832dd53bdabb0f061b26931cb777cf52acbcae020dbc4d1c4dc7a0ddb7ee
```

Independent checks verified the anonymous image manifest, exact configuration
bytes and hash, signed SNP/TDX predicate, source commit, immutable tag and hosted
signing workflow. Only the independent root public key is in configuration.

A real 2-CPU/8-GiB confidential Tinfoil VM booted this release. The Go verifier
accepted its hardware attestation and attested TLS and rejected a wrong release
pin. The service exposed a fresh waiting nonce, denied unsigned initialization,
and kept application routes closed. Initial attestation fetches returned 503
until routing became available; verification was never bypassed. No runtime
credentials or owner enrollment were sent. The empty proof VM was stopped.

This is startup and bootstrap-boundary evidence. It does not prove initialized
controller operation, automatic storage renewal, a confidential agent process,
or 100 simultaneous browsers. Those require separate acceptance. The controller
is a trusted authority over its enrolled owners; agents must not receive its
keys, IAM authority or administration endpoint.

## Readiness fix — release 2

[Release controller-proof-20261005-2](https://github.com/1patch/confidential-browser-controller/releases/tag/controller-proof-20261005-2)
adds bounded, read-only worker readiness checks for the interval between cloud
`running` status and availability of the attested public shim. Rejected evidence,
channel-binding failures, bootstrap writes and browser actions are never retried.

Image source: `a6fa24fcb8a831cd4369647e1f820265e3aca2e1`.
Configuration source: `9eada0d4c2d708cf55a583fa42f26b44cdf026f4`.

```
ghcr.io/1patch/confidential-browser-controller@sha256:c8b89ddea67319909b61104260bee3650bdf98f81d3c18a5d756af358ca559e9
```

The [image acceptance workflow](https://github.com/1patch/confidential-browser-controller/actions/runs/37393727936)
and [measurement workflow](https://github.com/1patch/confidential-browser-controller/actions/runs/37394236519)
passed. The independently verified measured manifest is:

```
sha256:8f448201fafd9292ac77f4245ea8e6da52fba259dec107b7f19dde617b6e4cde
```

Anonymous pull access, exact configuration bytes, configuration hash, VM shape,
hosted signer, source/tag and signed measurement predicate all matched. This
release retains the independent public root authority. The existing empty proof VM was upgraded to this exact release. Actual hardware
attestation and attested TLS passed, a wrong release pin was rejected, unsigned
bootstrap was denied and application routes remained closed. Runtime credentials
and enrollment were not delivered. The empty proof VM was then stopped.
Runtime initialization and automatic worker lifecycle remain separate gates.

## Explicit Pi runtime — release 3

[Release controller-proof-20261005-3](https://github.com/1patch/confidential-browser-controller/releases/tag/controller-proof-20261005-3)
adds an explicit immutable Pi worker mode. Browser-only enrollment continues
rejecting inference credentials. The controller image contains neither Chromium
nor the Pi/application runtime.

Image source: `4b42aeb110ca806eee4133fd18a708a35d004efc`.
Configuration source: `76510f6d48ba4f9afbed66c6dd2f05eaacadfd62`.

```
ghcr.io/1patch/confidential-browser-controller@sha256:b9135a9d1879f6f5ec0196a1f38384340654d8aea5645a14fe14ce51323cc75c
```

The [image acceptance](https://github.com/1patch/confidential-browser-controller/actions/runs/37397610876)
and [measurement](https://github.com/1patch/confidential-browser-controller/actions/runs/37398001199)
workflows passed. Independent anonymous image, exact configuration, source/tag,
hosted signing workflow and signed SNP/TDX verification matched manifest:

```
sha256:001812b7af7dce5ffda0ec55c096cfe9167bd10e4cec452d7f978cb2a6d82b57
```

The actual confidential VM accepted the correct release pin and rejected a wrong
one. Unsigned bootstrap was denied; all application routes, including `/v1/agent`,
remained closed. No enrollment or runtime credentials were delivered. The VM was
stopped after verification. Initialized lifecycle and automatic maintenance
remain unproven; a restricted provisioning key is required before enrollment.

## Standard release workflow — release 4

`controller-proof-20261005-4` at source
`d190d0137b5ff58034d94b173d5203a0a8fe28f7` adds Tinfoil's required release workflow
layout. The [prepare job](https://github.com/1patch/confidential-browser-controller/actions/runs/37404255363)
and [publish job](https://github.com/1patch/confidential-browser-controller/actions/runs/37404271440)
passed. Independent signature verification binds the exact source/tag and hosted
`tinfoil-release-publish.yml`. Image, configuration bytes and the measured manifest
are identical to release 3. Actual read-only Tinfoil create preflight now returns
HTTP 200, valid, and no errors. No VM or runtime enrollment was created by that
check; release-3 hardware evidence remains the latest actual startup proof.
