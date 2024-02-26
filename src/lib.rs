//! Decodes the AWS Account ID given an AWS Access Key ID (with a four-letter resource identifier
//! beginning with "A"; this does not work for older key IDs beginning with "I" or "J"). There is
//! also a function to return the resource type associated with a key ID prefix as helpful context.
//!
//! # Example
//!
//! ```rust
//! use aws_account_id_from_key_id::*;
//!
//! fn main() {
//!     let access_key_id = "AKIASP2TPHJSQH3FJXYZ";
//!
//!     // Decode AWS account ID given AWS access key ID
//!     assert_eq!(get_aws_account_id(&access_key_id).unwrap(), "171436882533");
//!
//!     // Get associated AWS resource type given AWS access key ID
//!     assert_eq!(get_associated_resource_type(&access_key_id).unwrap(), "Access key");
//! }
//! ```
//!
//! # References / Credit
//!
//! This is primarily based on [the research and Python PoC code by Tal
//! Be'ery.](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
//!
//! - [A short note on AWS KEY ID](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
//! - [AWS Access Key ID formats](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html)
//! - [AWS security credential formats](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/)
//! - [Get Account ID from AWS Access Keys](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/)
//! - [Research Uncovers AWS Account Numbers Hidden in Access Keys](https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys)
//! - [TruffleHog AWS Detector Code](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/aws.go)
//! - [Understanding unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes)

use std::collections::HashMap;

/// Returns hashmap with AWS key ID associated resource types for lookup of key prefixes.
fn get_resource_lookup_hashmap() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("ABIA", "AWS STS service bearer token"),
        ("ACCA", "Context-specific credential"),
        ("AGPA", "User group"),
        ("AIDA", "IAM user"),
        ("AIPA", "Amazon EC2 instance profile"),
        ("AKIA", "Access key"),
        ("ANPA", "Managed policy"),
        ("ANVA", "Version in a managed policy"),
        ("APKA", "Public key"),
        ("AROA", "Role"),
        ("ASCA", "Certificate"),
        ("ASIA", "Temporary (AWS STS) access key IDs"),

    ])
}

/// Get associated resource type given AWS key ID.
///
/// An AWS key ID (`key_id`) has a four-character prefix that identifies the associated resource
/// type. Only prefixes for newer key IDs are supported (older key ID prefixes beginning with "I"
/// or "J" are unsupported).
///
/// # References
///
/// - [Understanding unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes)
/// - [A short note on AWS KEY ID](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
pub fn get_associated_resource_type(key_id: &str) -> Option<&'static str> {
    if key_id.trim().len() < 4 { return None; }
    let map = get_resource_lookup_hashmap();
    map.get(key_id.trim()[..4].to_uppercase().as_str()).copied()
}

/// Base32 decoder helper function
fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut num_bits = 0;

    for ch in encoded.chars() {
        let val = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,  // I think L and O are excluded but this works
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return None // Invalid character
        };

        buffer = (buffer << 5) | val;
        num_bits += 5;

        if num_bits >= 8 {
            num_bits -= 8;
            result.push((buffer >> num_bits) as u8);
            buffer &= (1 << num_bits) - 1;
        }
    }

    if num_bits >= 5 || buffer != 0 {
        None // Invalid input length or padding
    } else {
        Some(result)
    }
}

/// Decodes the AWS account ID given an AWS access key ID.
///
/// Only key IDs with four-letter resource identifier prefixes beginning with "A" are supported
/// (this does not work for older key IDs beginning with "I" or "J").
pub fn get_aws_account_id(key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // basic length check
    if key_id.trim().len() < 14 {  // probably should increase this check to 20
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                       "key ID input too short").into());
    }

    let trimmed_key_id = key_id.trim()[4..].to_uppercase();
    if let Some(b32_decoded) = base32_decode(&trimmed_key_id) {
        // there needs to be at least 6 bytes for the next step
        if b32_decoded.len() < 6 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                           "key ID input too short").into());
        }
        let y = &b32_decoded[..6];

        // convert from big-endian bytes to integer then bitwise AND + shift
        let z = u64::from_be_bytes([0, 0, y[0], y[1], y[2], y[3], y[4], y[5]]);
        let mask = u64::from_str_radix("7fffffffff80", 16).unwrap();
        let e = (z & mask) >> 7;

        return Ok(e.to_string());
    } else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                       "unable to base32 decode key ID").into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests all supported AWS access key ID prefixes, sample access key IDs, an invalid prefix,
    /// and an empty string for expected return values.
    #[test]
    fn key_id_prefix_resource_types_match() {
        let map = get_resource_lookup_hashmap();
        for (prefix, resource_type) in &map {
            assert_eq!(get_associated_resource_type(*prefix).unwrap(), *resource_type);
        }
        assert_eq!(get_associated_resource_type("AIDASP2TPHJSUFRSTTZX4").unwrap(),
                   "IAM user");
        assert_eq!(get_associated_resource_type("ASIAY34FZKBOKMUTVV7A").unwrap(),
                   "Temporary (AWS STS) access key IDs");
        assert_eq!(get_associated_resource_type("IPAD"), None);
        assert_eq!(get_associated_resource_type(""), None);
    }

    /// Tests whether the AWS account ID was properly decoded from given AWS access key IDs and
    /// also checks that invalid key IDs return errors.
    ///
    /// # Sources for test key IDs and associated account IDs
    ///
    /// - [A short note on AWS KEY ID](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
    /// - [TruffleHog AWS Detectors Tests](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/aws_test.go)
    #[test]
    fn account_id_decoded_from_key_id() {
        assert_eq!(get_aws_account_id("ASIAY34FZKBOKMUTVV7A").unwrap(), "609629065308");
        assert_eq!(get_aws_account_id("AKIASP2TPHJSQH3FJRUX").unwrap(), "171436882533");
        assert_eq!(get_aws_account_id("AKIASP2TPHJSQH3FJXYZ").unwrap(), "171436882533");
        assert_eq!(get_aws_account_id("AKIASP2TPHJS").is_err(), true);
        assert_eq!(get_aws_account_id("AKIA").is_err(), true);
        assert_eq!(get_aws_account_id("cheeseburger").is_err(), true);
        assert_eq!(get_aws_account_id("AKIASP1TPHJSQH8FJXYZ").is_err(), true);
    }
}
