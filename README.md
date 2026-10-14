# ZKPC

**Zero-Knowledge Proofs for Hardware-Bound Credentials**

ZKPC explores using zero-knowledge proofs to verify hardware-bound credentials without exposing the device's hardware public key to the verifier.

The design combines platform attestation, signed credentials, P-256 ECDSA verification inside an R1CS circuit, and service-specific pseudonyms derived from a committed secret.

## Protocol

Enrollment Authority (EA) validates platform evidence and issues a credential binding the device key \(K_{\mathrm{dev}}\) to a secret commitment:

\[
\mathcal{C}=[s]G
\]

For a verifier challenge bound to a service and policy, the device signs the challenge using its hardware key and generates a proof of credential validity, key possession, and pseudonym consistency.

The service-specific pseudonym is:

\[
P_{\mathrm{svc}}=[s]P_{\mathrm{base}}
\]

\[
P_{\mathrm{base}}=
\operatorname{hash\_to\_curve}(\mathrm{service\_id})
\]

The construction uses RFC 9380 hash-to-curve with Simplified SWU on P-256.

Hardware assurance depends on correct platform-attestation validation and credential issuance. The proof establishes only the cryptographic relationships enforced by the implemented circuit.

## Cryptographic implementation

ZKPC uses R1CS circuits and the Vega proving infrastructure. The P-256 coordinate field is matched to `halo2curves::t256::Fq`, allowing native coordinate arithmetic. ECDSA scalar operations remain modulo the curve order \(n\).

\[
w=s_{\mathrm{sig}}^{-1}\pmod n
\]

\[
u_1=ew\pmod n,\qquad u_2=rw\pmod n
\]

\[
R=u_1G+u_2Q,\qquad x(R)\bmod n=r
\]

Here, \(s_{\mathrm{sig}}\) is the ECDSA signature scalar, distinct from the committed secret \(s\).

## Preliminary ECDSA benchmarks

Reported measurements for the standalone P-256 ECDSA circuit:

| Metric | Measurement |
|---|---:|
| Constraints | 59,157 |
| Setup | 225.4 ms |
| Total proving | 49.60 ms |
| Verification | 32.03 ms |
| Proof size | 74,145 bytes |

These are preliminary primitive-level results, not measurements of the complete presentation proof.

## Workspace

- `zkpc-core`: Credentials, statements and protocol primitives
- `zkpc-circuits`: R1CS circuits and cryptographic constraints
- `zkpc-ea`: Enrollment Authority and platform attestation
- `zkpc-verifier`: Proof verification
- `zkpc-agent`: Device and hardware integration
- `zkpc-prover`: Proof generation
- `zkpc-sdk`: Integration library
- `zkpc-cli`: Command-line interface
- `zkpc-testkit`: Test fixtures and mocks

## Build and test

Requires a compatible Rust toolchain and platform-specific dependencies where applicable.

```bash
cargo build --release --workspace
cargo test -p zkpc-circuits --lib --release
cargo test -p zkpc-ea -p zkpc-verifier --release
```

ZKPC remains under active development. End-to-end behavior, security properties, and performance are subject to validation against the completed implementation.

## License

Apache License 2.0. See `LICENSE`.
