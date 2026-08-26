#[must_use]
pub fn redact(input: &str) -> String {
    let mut output = input.to_owned();
    for marker in ["Bearer ", "bearer "] {
        let mut cursor = 0;
        while let Some(relative_start) = output[cursor..].find(marker) {
            let value_start = cursor + relative_start + marker.len();
            let value_len = output[value_start..]
                .find(|character: char| {
                    character.is_whitespace() || character == '"' || character == '}'
                })
                .unwrap_or(output.len() - value_start);
            output.replace_range(value_start..value_start + value_len, "[REDACTED]");
            cursor = value_start + "[REDACTED]".len();
        }
    }
    for key in [
        "ticket",
        "native_access_token",
        "control_capability",
        "password",
        "refresh_token",
        "access_token",
    ] {
        let needle = format!("\"{key}\":\"");
        let mut cursor = 0;
        while let Some(relative_start) = output[cursor..].find(&needle) {
            let value_start = cursor + relative_start + needle.len();
            let Some(end) = output[value_start..].find('"') else {
                break;
            };
            output.replace_range(value_start..value_start + end, "[REDACTED]");
            cursor = value_start + "[REDACTED]".len();
        }
    }
    output
}
