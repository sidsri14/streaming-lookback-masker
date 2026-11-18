use streaming_lookback_masker::StreamingLookbackMasker;

#[test]
fn test_baseline_single_chunk_secret() {
    let mut masker = StreamingLookbackMasker::standard();
    let input = b"Hello, here is your key: sk-proj-1234567890abcdefghijk. Keep it safe!";

    let mut output = masker.process_chunk(input);
    output.extend_from_slice(&masker.flush());

    let result = String::from_utf8(output).unwrap();
    assert!(result.contains("[REDACTED_API_KEY]"));
    assert!(!result.contains("sk-proj-1234567890abcdefghijk"));
    assert!(result.starts_with("Hello, here is your key: "));
    assert!(result.ends_with(". Keep it safe!"));
    assert_eq!(masker.total_matches(), 1);
}

#[test]
fn test_split_secret_across_two_chunks() {
    let mut masker = StreamingLookbackMasker::standard();

    // The secret is "sk-proj-1234567890abcdefghijk"
    // Chunk 1 cuts right after "sk-"
    let chunk1 = b"Assistant: Please export OPENAI_API_KEY=sk-";
    let chunk2 = b"proj-1234567890abcdefghijk in your bashrc file.";

    let mut output = Vec::new();
    output.extend(masker.process_chunk(chunk1));
    output.extend(masker.process_chunk(chunk2));
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    println!("Two chunks result: {}", result);

    assert!(result.contains("OPENAI_API_KEY=[REDACTED_API_KEY] in your bashrc"));
    assert!(!result.contains("sk-proj-1234567890abcdefghijk"));
    assert_eq!(masker.total_matches(), 1);
}

#[test]
fn test_split_secret_across_three_chunks() {
    let mut masker = StreamingLookbackMasker::standard();

    // Secret: sk-ant-api03-abcdef1234567890123456
    let chunk1 = b"Use this Anthropic token: sk-ant-";
    let chunk2 = b"api03-abcdef";
    let chunk3 = b"1234567890123456 for authentication.";

    let mut output = Vec::new();
    output.extend(masker.process_chunk(chunk1));
    output.extend(masker.process_chunk(chunk2));
    output.extend(masker.process_chunk(chunk3));
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    println!("Three chunks result: {}", result);

    assert!(result.contains("Use this Anthropic token: [REDACTED_API_KEY] for authentication."));
    assert!(!result.contains("sk-ant-api03-abcdef1234567890123456"));
    assert_eq!(masker.total_matches(), 1);
}

#[test]
fn test_split_byte_by_byte_pathological() {
    let mut masker = StreamingLookbackMasker::standard();

    let full_text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload1234567890\n";
    let mut output = Vec::new();

    // Deliver the entire secret 1 single byte per chunk!
    for b in full_text.bytes() {
        output.extend(masker.process_chunk(&[b]));
    }
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    println!("Byte-by-byte result: {}", result);

    assert_eq!(result, "Authorization: Bearer [REDACTED_TOKEN]\n");
    assert_eq!(masker.total_matches(), 1);
}

#[test]
fn test_prefix_false_alarm_no_corruption() {
    let mut masker = StreamingLookbackMasker::standard();

    // Starts with "sk-" but is just normal text, not a 20+ char secret
    let chunk1 = b"The ski resort in Aspen has ";
    let chunk2 = b"great powder today.";

    let mut output = Vec::new();
    output.extend(masker.process_chunk(chunk1));
    output.extend(masker.process_chunk(chunk2));
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    assert_eq!(result, "The ski resort in Aspen has great powder today.");
    assert_eq!(masker.total_matches(), 0);
}

#[test]
fn test_sse_streaming_chunk_boundary_split() {
    let mut masker = StreamingLookbackMasker::standard();

    // Simulating raw OpenAI SSE network frames split mid-stream at packet boundary
    let packet1 = b"data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"sk-proj-";
    let packet2 = b"998877665544332211aabbcc\"}}]}\n\n";
    let packet3 = b"data: [DONE]\n\n";

    let mut output = Vec::new();
    output.extend(masker.process_chunk(packet1));
    output.extend(masker.process_chunk(packet2));
    output.extend(masker.process_chunk(packet3));
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    println!("SSE Stream result:\n{}", result);

    assert!(result.contains("[REDACTED_API_KEY]"));
    assert!(!result.contains("998877665544332211aabbcc"));
    assert!(result.contains("data: [DONE]"));
}

#[test]
fn test_no_secret_passthrough_byte_exact() {
    let mut masker = StreamingLookbackMasker::standard();
    let text = "Here is a standard markdown explanation without any credentials.\n- Point 1\n- Point 2\nDone.";

    let mut output = Vec::new();
    for chunk in text.as_bytes().chunks(7) {
        output.extend(masker.process_chunk(chunk));
    }
    output.extend(masker.flush());

    let result = String::from_utf8(output).unwrap();
    assert_eq!(result, text);
    assert_eq!(masker.total_matches(), 0);
}
