use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::ApiError;

pub fn pem_for_certificates(certificates: &[Vec<u8>]) -> String {
    let mut output = String::new();
    for der in certificates {
        output.push_str("-----BEGIN CERTIFICATE-----\r\n");
        let encoded = STANDARD.encode(der);
        for chunk in encoded.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            output.push_str("\r\n");
        }
        output.push_str("-----END CERTIFICATE-----\r\n");
    }
    output
}

pub fn c_expression_for_certificates(certificates: &[Vec<u8>]) -> String {
    let pem = pem_for_certificates(certificates);
    let lines: Vec<&str> = pem
        .strip_suffix("\r\n")
        .unwrap_or(&pem)
        .split("\r\n")
        .collect();
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let suffix = if index + 1 == lines.len() { "" } else { " +" };
            format!("\"{}\\r\\n\"{}", escape_c_string(line), suffix)
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn escape_c_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\x{:02X}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

pub fn select_certificates(all: &[Vec<u8>], indices: &[usize]) -> Result<Vec<Vec<u8>>, ApiError> {
    if indices.is_empty() {
        return Err(ApiError::invalid(
            "invalid_selection",
            "Select at least one certificate.",
        ));
    }

    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != indices.len() {
        return Err(ApiError::invalid(
            "invalid_selection",
            "The certificate selection contains duplicates.",
        ));
    }

    sorted
        .into_iter()
        .map(|index| {
            all.get(index).cloned().ok_or_else(|| {
                ApiError::invalid(
                    "invalid_selection",
                    "The certificate selection is out of range.",
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        c_expression_for_certificates, escape_c_string, pem_for_certificates, select_certificates,
    };

    #[test]
    fn pem_uses_crlf_and_wraps_at_64_characters() {
        let pem = pem_for_certificates(&[vec![0_u8; 60]]);
        assert!(pem.ends_with("-----END CERTIFICATE-----\r\n"));
        assert!(!pem.replace("\r\n", "").contains('\n'));
        let body: Vec<&str> = pem
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.starts_with("-----END"))
            .collect();
        assert_eq!(body[0].len(), 64);
        assert_eq!(body[1].len(), 16);
    }

    #[test]
    fn c_expression_contains_literal_newlines_and_no_trailing_plus() {
        let output = c_expression_for_certificates(&[vec![1, 2, 3]]);
        assert!(output.starts_with("\"-----BEGIN CERTIFICATE-----\\r\\n\" +\r\n"));
        assert!(output.ends_with("\"-----END CERTIFICATE-----\\r\\n\""));
        assert!(!output.ends_with('+'));
    }

    #[test]
    fn selection_is_returned_in_chain_order() {
        let selected = select_certificates(&[vec![0], vec![1], vec![2]], &[2, 0]).unwrap();
        assert_eq!(selected, vec![vec![0], vec![2]]);
    }

    #[test]
    fn rejects_duplicate_selection() {
        assert!(select_certificates(&[vec![0]], &[0, 0]).is_err());
    }

    #[test]
    fn escapes_c_string_characters() {
        assert_eq!(escape_c_string("a\\\"\t"), "a\\\\\\\"\\t");
    }
}
