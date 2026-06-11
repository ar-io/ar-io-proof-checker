module github.com/ar-io/ar-io-proof-checker/wasm

go 1.25.0

require github.com/ar-io/ar-io-agent v0.0.0

require github.com/gowebpki/jcs v1.0.1 // indirect

// The agent source is materialized at the PINNED commit by
// scripts/build-wasm.sh (a detached git worktree — the shared sibling
// checkout is never disturbed). Never points at a live checkout's HEAD.
replace github.com/ar-io/ar-io-agent => ./agent-src
