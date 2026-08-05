# mesh-llm-identity

Shared owner identity and message-envelope crypto for Mesh LLM crates.

This crate owns dependency-light identity primitives that are needed by both the
host runtime and embedded clients:

- owner keypair generation and owner ID derivation
- signed-and-encrypted control-message envelopes
- key provider traits for client/runtime integration
- shared crypto error types

The default feature set stays pure and does not depend on host filesystem or
secret-provider clients. This keeps embedded/client dependency graphs free of
local machine policy.

Enable `host-io` for host-facing binaries and runtime crates that need
secret-provider access, encrypted keystore files, node key files, ownership
certificates, or trust-store persistence. Legacy public symbols retain
`keychain` in their names for source compatibility, but credential I/O goes
through the configured `daz-secrets` provider and never calls an OS keychain.
