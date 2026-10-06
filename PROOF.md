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
