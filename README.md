# yubihsm-parse-attestation

Parses the custom extensions on YubiHSM 2 attestation certificates and displays them in a human friendly manner. For more information about YubiHSM 2 attestations, see our [developer documentation](https://developers.yubico.com/YubiHSM2/Concepts/Attestation.html).

---
**NOTE:** This utility does not verify the supplied certificate has a chain back to a trusted certificate authority. You must verify this before relying on the output of this utility.

---

## Installation

Binaries are available on the [Releases](https://github.com/YubicoLabs/yubihsm-parse-attestation/releases) page. You can also install from source using the command below.

```
go install github.com/YubicoLabs/yubihsm-parse-attestation@latest
```

## Usage

```
yubihsm-parse-attestation <path_to_attestation_cert>
```

The `--format` flag can be used to specify `json` or `yaml` output.
