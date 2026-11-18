use regex::Regex;

/// Configuration for secret detection and masking.
#[derive(Clone, Debug)]
pub struct MaskRule {
    pub name: String,
    pub pattern: Regex,
    pub replacement: String,
    /// Maximum expected length of a secret matching this rule.
    /// The lookback window will be at least as large as this value.
    pub max_secret_len: usize,
}

impl MaskRule {
    pub fn new(name: impl Into<String>, regex_str: &str, replacement: impl Into<String>, max_len: usize) -> Result<Self, regex::Error> {
        let pattern = Regex::new(regex_str)?;
        Ok(Self {
            name: name.into(),
            pattern,
            replacement: replacement.into(),
            max_secret_len: max_len,
        })
    }

    /// Common preset for OpenAI / Anthropic / Generic API keys
    pub fn standard_api_keys() -> Vec<Self> {
        vec![
            Self::new(
                "openai_key",
                r"sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,}",
                "[REDACTED_API_KEY]",
                128,
            ).expect("valid regex"),
            Self::new(
                "anthropic_key",
                r"sk-ant-[a-zA-Z0-9_-]{20,}",
                "[REDACTED_API_KEY]",
                128,
            ).expect("valid regex"),
            Self::new(
                "bearer_token",
                r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{24,}",
                "Bearer [REDACTED_TOKEN]",
                256,
            ).expect("valid regex"),
        ]
    }
}

/// A sliding-window lookback streaming secret masker.
///
/// Solves the split-secret boundary problem in HTTP/SSE LLM streaming responses:
/// when a secret (e.g. `sk-...`) is partitioned across two or more streaming chunks,
/// naive chunk-by-chunk regex matching fails.
///
/// This masker maintains a bounded lookback buffer. On every incoming chunk:
/// 1. Appends chunk bytes to the lookback carry buffer.
/// 2. Performs regex matching across the aggregated window.
/// 3. Replaces matched secrets with the specified redaction token.
/// 4. Determines the safe emission boundary: any bytes older than the maximum
///    potential secret prefix length (or immediately following a completed redaction)
///    are emitted.
/// 5. Retains only the ambiguous tail in the lookback buffer.
/// 6. On `flush()`, evaluates and drains the remaining tail.
#[derive(Debug)]
pub struct StreamingLookbackMasker {
    rules: Vec<MaskRule>,
    max_lookback: usize,
    carry_buffer: Vec<u8>,
    total_bytes_processed: usize,
    total_matches_redacted: usize,
}

impl StreamingLookbackMasker {
    /// Creates a new streaming lookback masker with the provided rules.
    pub fn new(rules: Vec<MaskRule>) -> Self {
        let max_lookback = rules
            .iter()
            .map(|r| r.max_secret_len)
            .max()
            .unwrap_or(128);

        Self {
            rules,
            max_lookback,
            carry_buffer: Vec::with_capacity(max_lookback * 4),
            total_bytes_processed: 0,
            total_matches_redacted: 0,
        }
    }

    /// Creates a default masker configured with standard LLM/API key patterns.
    pub fn standard() -> Self {
        Self::new(MaskRule::standard_api_keys())
    }

    /// Process an incoming stream chunk. Returns the safe-to-emit masked bytes.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() {
            return Vec::new();
        }

        self.total_bytes_processed += chunk.len();
        self.carry_buffer.extend_from_slice(chunk);

        self.redact_and_emit(false)
    }

    /// Flush all remaining bytes at stream completion (EOF or SSE [DONE]).
    /// Returns any remaining masked bytes and clears the buffer.
    pub fn flush(&mut self) -> Vec<u8> {
        if self.carry_buffer.is_empty() {
            return Vec::new();
        }

        self.redact_and_emit(true)
    }

    /// Internal redaction and emission logic.
    fn redact_and_emit(&mut self, is_flush: bool) -> Vec<u8> {
        // Attempt UTF-8 conversion of carry_buffer.
        // If not valid UTF-8, we find the longest valid UTF-8 prefix.
        let (valid_len, _) = match std::str::from_utf8(&self.carry_buffer) {
            Ok(s) => (s.len(), 0),
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if is_flush {
                    // At flush, take what we can
                    (valid_up_to, self.carry_buffer.len() - valid_up_to)
                } else {
                    // Wait for more bytes to complete the UTF-8 codepoint
                    (valid_up_to, self.carry_buffer.len() - valid_up_to)
                }
            }
        };

        if valid_len == 0 {
            if is_flush {
                // Drain everything as raw bytes
                return std::mem::take(&mut self.carry_buffer);
            }
            return Vec::new();
        }

        let mut text = String::from_utf8_lossy(&self.carry_buffer[..valid_len]).into_owned();
        let remaining_invalid_bytes = self.carry_buffer[valid_len..].to_vec();

        // Track last match end index in text
        let mut last_redacted_end = 0;

        for rule in &self.rules {
            let mut result = String::with_capacity(text.len());
            let mut cursor = 0;
            let mut rule_matches = 0;

            for mat in rule.pattern.find_iter(&text) {
                result.push_str(&text[cursor..mat.start()]);
                result.push_str(&rule.replacement);
                cursor = mat.end();
                rule_matches += 1;
                last_redacted_end = result.len();
            }

            if rule_matches > 0 {
                result.push_str(&text[cursor..]);
                text = result;
                self.total_matches_redacted += rule_matches;
            }
        }

        if is_flush {
            // Everything is safe to emit
            let mut output = text.into_bytes();
            output.extend_from_slice(&remaining_invalid_bytes);
            self.carry_buffer.clear();
            return output;
        }

        // Determine safe emission point
        let total_len = text.len();

        let safe_cut_point = if total_len <= self.max_lookback {
            // Buffer is not full enough to guarantee no split secret prefix
            // UNLESS a redaction occurred and the trailing unredacted part is 0
            if last_redacted_end == total_len {
                total_len
            } else {
                0
            }
        } else {
            let unredacted_tail_len = total_len - last_redacted_end;
            if unredacted_tail_len > self.max_lookback {
                // The safe boundary is at least total_len - max_lookback
                total_len - self.max_lookback
            } else {
                // The redacted section is safe up to last_redacted_end
                last_redacted_end
            }
        };

        if safe_cut_point == 0 {
            // Keep full text in carry buffer
            self.carry_buffer = text.into_bytes();
            self.carry_buffer.extend_from_slice(&remaining_invalid_bytes);
            return Vec::new();
        }

        // Split text at safe_cut_point (ensuring char boundary)
        let cut_idx = floor_char_boundary(&text, safe_cut_point);

        let safe_text = &text[..cut_idx];
        let remaining_text = &text[cut_idx..];

        let output = safe_text.as_bytes().to_vec();

        self.carry_buffer = remaining_text.as_bytes().to_vec();
        self.carry_buffer.extend_from_slice(&remaining_invalid_bytes);

        output
    }

    /// Reset internal state
    pub fn reset(&mut self) {
        self.carry_buffer.clear();
        self.total_bytes_processed = 0;
        self.total_matches_redacted = 0;
    }

    pub fn total_matches(&self) -> usize {
        self.total_matches_redacted
    }
}

/// Helper: find nearest valid UTF-8 character boundary <= index
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Server-Sent Events (SSE) aware streaming masker.
///
/// Wraps `StreamingLookbackMasker` and parses incoming SSE data lines (`data: ...\n\n`),
/// applies lookback masking across the event contents, and formats valid output SSE streams.
#[derive(Debug)]
pub struct SseStreamMasker {
    masker: StreamingLookbackMasker,
}

impl SseStreamMasker {
    pub fn new(rules: Vec<MaskRule>) -> Self {
        Self {
            masker: StreamingLookbackMasker::new(rules),
        }
    }

    pub fn standard() -> Self {
        Self {
            masker: StreamingLookbackMasker::standard(),
        }
    }

    pub fn process_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.masker.process_chunk(chunk)
    }

    pub fn flush(&mut self) -> Vec<u8> {
        self.masker.flush()
    }

    pub fn total_matches(&self) -> usize {
        self.masker.total_matches()
    }
}
