# Streaming Lookback Secret Masker (POC for Sparcle / Bolt)

A bounded-buffer sliding-window streaming secret masker in Rust, designed specifically for HTTP/SSE LLM gateways and proxies (such as Bolt and Agent Gateway).

It guarantees that sensitive tokens (API keys, Bearer tokens, private keys) are reliably detected and masked even when partitioned across arbitrary chunk boundaries in streaming Server-Sent Events (SSE).

---

## The Problem: Boundary-Split Secrets in Streaming LLMs

In streaming LLM proxies, upstream completions arrive in non-deterministic chunk boundaries:

```text
Chunk 1: "Assistant: Please export OPENAI_API_KEY=sk-"
Chunk 2: "proj-1234567890abcdefghijk in your bashrc."
```

If an LLM gateway attempts stateless, chunk-by-chunk regex masking:
- `Chunk 1` is evaluated in isolation: regex pattern `sk-[a-zA-Z0-9_-]{20,}` does **not** match (`sk-` is too short).
- `Chunk 2` is evaluated in isolation: `proj-123456...` does **not** match (`sk-` prefix is missing).
- **Result**: The secret leaks unmasked to the client.

A similar vulnerability occurs when users stream byte-by-byte or when chunks cut mid-token.

---

## Architectural Solution: Bounded Lookback Window

The `StreamingLookbackMasker` introduces a constant-bounded lookback buffer:

```text
Incoming Chunk  ──► [ Carry Buffer (Tail <= W) ] ──► Regex Redaction Across Window
                            ▲                                    │
                            │                                    ▼
                     Retain Ambiguous Tail            Safe Emission Boundary (L - W)
                     (Length <= MaxSecretLen)                    │
                                                                 ▼
                                                        Emit Masked Bytes
```

### Core Invariants:
1. **Window Size Bound ($W$)**: $W = \max(\text{rule}.\text{max\_secret\_len})$. Memory footprint never exceeds $O(W + \text{chunk\_size})$, preventing memory bloat during multi-hour streaming sessions.
2. **Safe Emission Cut Point**:
   - Any bytes older than $W$ bytes from the trailing edge are mathematically guaranteed not to be a prefix of a secret split into the *next* chunk.
   - Any completed redaction token (`[REDACTED_API_KEY]`) is immediately safe to emit up to its boundary.
3. **Stream Completion (`flush`)**:
   - On SSE `[DONE]` or connection EOF, `flush()` scans the remaining tail and drains the carry buffer with zero lingering bytes.

---

## Included Split-Secret Test Cases

The test suite (`tests/split_secret_tests.rs`) covers every real-world streaming failure mode:

1. **`test_baseline_single_chunk_secret`**: Verifies normal inline masking when the entire secret is inside a single packet.
2. **`test_split_secret_across_two_chunks`**: Splits `sk-` into Chunk 1 and the remainder into Chunk 2. Verifies output replaces both chunks with `[REDACTED_API_KEY]`.
3. **`test_split_secret_across_three_chunks`**: Partitions a 32-character key across 3 distinct chunk boundaries (`sk-ant-` -> `api03-abcdef` -> `12345678...`).
4. **`test_split_byte_by_byte_pathological`**: Delivers a full Bearer token **1 single byte per chunk** across 66 consecutive chunks. Proves lookback aggregation handles extreme TCP packet fragmentation.
5. **`test_prefix_false_alarm_no_corruption`**: A chunk ending with `The ski resort in Aspen has ` followed by `great powder today.`. Proves false-alarm prefixes are preserved byte-for-byte without dropping characters.
6. **`test_sse_streaming_format_split`**: Real-world OpenAI SSE frames (`data: {"choices":[{"delta":{"content":"sk-proj-"}}]}\n\n`) split across event boundaries.
7. **`test_no_secret_passthrough_byte_exact`**: Verifies that standard prose streams through in small 7-byte chunks with zero byte corruption or alteration.

---

## Quick Verification

```bash
cargo check --tests
cargo test
```
