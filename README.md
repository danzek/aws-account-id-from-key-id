# Determine AWS Account ID from AWS Access Key ID

Decodes the AWS account ID given an AWS access key ID (with a four-letter resource identifier beginning with "A"; this does not work for older key IDs beginning with "I" or "J").

This is a small, single-file library with no dependencies outside `std`. Only two functions are exported / public
(there is an example of each below).

- [Crate](https://crates.io/crates/aws_account_id_from_key_id)
- [Read the documentation on Docs.rs](https://docs.rs/aws_account_id_from_key_id/0.8.2/aws_account_id_from_key_id/)

# Usage

This can be installed as [a crate](https://crates.io/crates/aws_account_id_from_key_id) via `cargo`.

`cargo add aws_account_id_from_key_id`

Once added as a dependency to a project, you can use it like so:

```rust
use aws_account_id_from_key_id::*;

fn main() {
    let access_key_id = "AKIASP2TPHJSQH3FJXYZ";

    // Decode AWS account ID given AWS access key ID
    assert_eq!(get_aws_account_id(&access_key_id).unwrap(), "171436882533");
    
    // Get associated AWS resource type given AWS access key ID
    assert_eq!(get_associated_resource_type(&access_key_id).unwrap(), "Access key");
}
```

# Rationale

## Isn't there a better way to do this?

Yes, use the AWS Security Token Service (STS) API call [`GetAccessKeyInfo`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html). Example:

    aws sts get-access-key-info --access-key-id=<key-id-goes-here>

## Why write this when perfectly-good Python and Go implementations already exist?

I mainly wrote this as a Rust programming language learning exercise. I'm open to feedback both to learn more about Rust and better ways to implement this as well as to fix any bugs / logic errors in the code.

# References / Credit

This is primarily based on [the research and Python PoC code by Tal Be'ery](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489).

- [A short note on AWS KEY ID](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
- [AWS Access Key ID formats](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html)
- [AWS security credential formats](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/)
- [Get Account ID from AWS Access Keys](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/)
- [Research Uncovers AWS Account Numbers Hidden in Access Keys](https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys)
- [TruffleHog AWS Detector Code](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/aws.go)
- [Understanding unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes)

# License

This project is released open source under the [MIT License](https://github.com/danzek/aws-account-id-from-key-id/blob/main/LICENSE).
