# Determine AWS Account ID from AWS Access Key ID

Decodes the AWS Account ID given an AWS Access Key ID (with a four-letter resource identifier beginning with "A"; this does not work for older key IDs beginning with "I" or "J").

# Usage

Coming soon....

# Rationale

*Why write this when perfectly-good Python and Go implementations already exist?*

I mainly wrote this as a Rust programming language learning exercise. I'm open to feedback both to learn more about Rust and better ways to implement this as well as to fix any bugs / logic errors in the code.

# References / Credit

This is primarily based on the research and Python PoC code provided by Tal Be'ery:

- [A short note on AWS KEY ID](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)

See also:

- [AWS Access Key ID formats](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html)
- [AWS security credential formats](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/)
- [Get Account ID from AWS Access Keys](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/)
- [Research Uncovers AWS Account Numbers Hidden in Access Keys](https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys)
- [TruffleHog AWS Detector Code](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/aws.go)

# License

This project is released open source under the [MIT License](https://github.com/danzek/aws-account-id-from-key-id/blob/main/LICENSE).
