use regex::Regex;

/// Configuration for secret detection and masking.
#[derive(Clone, Debug)]
pub struct MaskRule {
    pub name: String,
    pub pattern: Regex,
    pub replacement: String,
    /// Maximum expected length of a secret matching this rule.
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

    /// Common presets for OpenAI, Anthropic, and Generic Bearer API tokens
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
/// Handles arbitrary chunk fragmentation, streaming TCP splits, and byte-by-byte
/// delivery in LLM/SSE proxies.
#[derive(Debug)]
pub struct StreamingLookbackMasker {
    rules: Vec<MaskRule>,
    max_lookback: usize,
    carry_buffer: Vec<u8>,
    total_bytes_processed: usize,
    total_matches_redacted: usize,
}

impl StreamingLookbackMasker {
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

    pub fn standard() -> Self {
        Self::new(MaskRule::standard_api_keys())
    }

    pub fn process_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() {
            return Vec::new();
        }

        self.total_bytes_processed += chunk.len();
        self.carry_buffer.extend_from_slice(chunk);

        self.redact_and_emit(false)
    }

    pub fn flush(&mut self) -> Vec<u8> {
        if self.carry_buffer.is_empty() {
            return Vec::new();
        }

        self.redact_and_emit(true)
    }

    fn redact_and_emit(&mut self, is_flush: bool) -> Vec<u8> {
        let (valid_len, _) = match std::str::from_utf8(&self.carry_buffer) {
            Ok(s) => (s.len(), 0),
            Err(e) => (e.valid_up_to(), self.carry_buffer.len() - e.valid_up_to()),
        };

        if valid_len == 0 {
            if is_flush {
                return std::mem::take(&mut self.carry_buffer);
            }
            return Vec::new();
        }

        let mut text = String::from_utf8_lossy(&self.carry_buffer[..valid_len]).into_owned();
        let remaining_invalid_bytes = self.carry_buffer[valid_len..].to_vec();

        let mut last_match_end_in_original = 0;
        let mut touches_bleeding_edge = false;

        for rule in &self.rules {
            let mut result = String::with_capacity(text.len());
            let mut cursor = 0;
            let mut rule_matches = 0;

            for mat in rule.pattern.find_iter(&text) {
                // Critical streaming invariant:
                // If not flushing, and the match reaches the very end of the current buffer,
                // the secret may still be growing in subsequent chunks!
                // Hold this match until a delimiter closes it or EOF is reached.
                if !is_flush && mat.end() == text.len() {
                    touches_bleeding_edge = true;
                    break;
                }

                result.push_str(&text[cursor..mat.start()]);
                result.push_str(&rule.replacement);
                cursor = mat.end();
                rule_matches += 1;
                last_match_end_in_original = mat.end();
            }

            if rule_matches > 0 {
                result.push_str(&text[cursor..]);
                text = result;
                self.total_matches_redacted += rule_matches;
            }
        }

        if is_flush {
            let mut output = text.into_bytes();
            output.extend_from_slice(&remaining_invalid_bytes);
            self.carry_buffer.clear();
            return output;
        }

        let total_len = text.len();

        let safe_cut_point = if touches_bleeding_edge {
            // A match is currently active at the trailing edge of the buffer.
            // Retain from before the match start or keep bounded window.
            if total_len > self.max_lookback {
                total_len - self.max_lookback
            } else {
                0
            }
        } else if total_len <= self.max_lookback {
            0
        } else {
            // Buffer is larger than max_lookback.
            // Any bytes older than max_lookback cannot be part of an incoming prefix.
            total_len - self.max_lookback
        };

        if safe_cut_point == 0 {
            self.carry_buffer = text.into_bytes();
            self.carry_buffer.extend_from_slice(&remaining_invalid_bytes);
            return Vec::new();
        }

        let cut_idx = floor_char_boundary(&text, safe_cut_point);

        let safe_text = &text[..cut_idx];
        let remaining_text = &text[cut_idx..];

        let output = safe_text.as_bytes().to_vec();

        self.carry_buffer = remaining_text.as_bytes().to_vec();
        self.carry_buffer.extend_from_slice(&remaining_invalid_bytes);

        output
    }

    pub fn reset(&mut self) {
        self.carry_buffer.clear();
        self.total_bytes_processed = 0;
        self.total_matches_redacted = 0;
    }

    pub fn total_matches(&self) -> usize {
        self.total_matches_redacted
    }
}

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
