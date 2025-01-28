// Copyright 2021 Yubico AB

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// OIDs for custom extensions
	baseOID         = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 4})
	firmwareOID     = append(baseOID, 1)
	serialOID       = append(baseOID, 2)
	originOID       = append(baseOID, 3)
	domainsOID      = append(baseOID, 4)
	capabilitiesOID = append(baseOID, 5)
	objectIDOID     = append(baseOID, 6)
	labelOID        = append(baseOID, 9)
	fipsOID         = append(baseOID, 12)

	// YubiHSM origins
	// Do not change the order of these items, as the order relates to a bitmask
	origins = []string{
		"generated",
		"imported",
		"undefined",
		"undefined",
		"imported_wrapped",
	}

	// YubiHSM capabilities
	// Do not change the order of these items, as the order relates to a bitmask
	capabilities = []string{
		"get_opaque",
		"put_opaque",
		"put_authentication_key",
		"put_asymmetric_key",
		"generate_asymmetric",
		"sign_pkcs",
		"sign_pss",
		"sign_ecdsa",
		"sign_eddsa",
		"decrypt_pkcs",
		"decrypt_oaep",
		"derive_ecdh",
		"export_wrapped",
		"import_wrapped",
		"put_wrap_key",
		"generate_wrap_key",
		"exportable_under_wrap",
		"set_option",
		"get_option",
		"get_pseudo_random",
		"put_hmac_key",
		"generate_hmac_key",
		"sign_hmac",
		"verify_hmac",
		"get_log_entries",
		"sign_ssh_certificate",
		"get_template",
		"put_template",
		"reset_device",
		"decrypt_otp",
		"create_otp_aead",
		"randomize_otp_aead",
		"rewrap_from_otp_aead_key",
		"rewrap_to_otp_aead_key",
		"sign_attestation_certificate",
		"put_otp_aead_key",
		"generate_otp_aead_key",
		"wrap_data",
		"unwrap_data",
		"delete_opaque",
		"delete_authentication_key",
		"delete_asymmetric_key",
		"delete_wrap_key",
		"delete_hmac_key",
		"delete_template",
		"delete_otp_aead_key",
		"change_authentication_key",
		"put_symmetric_key",
		"generate_symmetric_key",
		"delete_symmetric_key",
		"decrypt_ecb",
		"encrypt_ecb",
		"decrypt_cbc",
		"encrypt_cbc",
		"put-public-wrap-key",
		"delete-public-wrap-key",
	}
)

type yubihsmAttestation struct {
	Device struct {
		Firmware string `json:"firmware"`
		Serial   int    `json:"serial"`
	} `json:"device"`
	Key struct {
		Origin       []string `json:"origin"`
		Domains      []int    `json:"domains"`
		Capabilities []string `json:"capabilities"`
		ID           int      `json:"id"`
		Label        string   `json:"label"`
		FIPS         bool     `json:"fips,omitempty"`
		Algorithm    string   `json:"algorithm"`
		Size         int      `json:"size"`
		RSAModulus   *big.Int `json:"modulus,omitempty"`
		RSAExponent  int      `json:"exponent,omitempty"`
		CurveName    string   `json:"curve,omitempty"`
	} `json:"key"`
}

func main() {
	cmd := cobra.Command{
		Short: "Parses YubiHSM 2 attestation custom certificate extensions",
		Use:   "yubihsm-parse-attestation <path_to_attestation_certificate>",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("format", cmd.PersistentFlags().Lookup("format")); err != nil {
				return fmt.Errorf("bind format flag: %w", err)
			}

			format := viper.GetString("format")
			if format != "yaml" && format != "json" {
				return fmt.Errorf("unsupported output format: %s", format)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("missing argument: path to certificate")
			}

			parsed, err := parseAttestation(args[0])
			if err != nil {
				return err
			}

			var marshalled []byte
			switch viper.GetString("format") {
			case "json":
				marshalled, err = json.Marshal(parsed)
				if err != nil {
					return fmt.Errorf("marshal parsed certificate: %w", err)
				}

			case "yaml":
				marshalled, err = yaml.Marshal(parsed)
				if err != nil {
					return fmt.Errorf("marshal parsed certificate: %w", err)
				}
			}

			fmt.Printf("%s", string(marshalled))

			return nil
		},
	}

	cmd.PersistentFlags().StringP("format", "f", "yaml", "Format for the output (yaml, json)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseAttestation(path string) (*yubihsmAttestation, error) {
	certBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	decoded, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(decoded.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	var parsed yubihsmAttestation

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		parsed.Key.Algorithm = "RSA"
		parsed.Key.RSAModulus = key.N
		parsed.Key.RSAExponent = key.E
		parsed.Key.Size = key.Size() * 8

	case *ecdsa.PublicKey:
		parsed.Key.Algorithm = "ECDSA"
		parsed.Key.CurveName = key.Params().Name
		parsed.Key.Size = key.Params().BitSize

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}

	for _, extension := range cert.Extensions {
		switch {
		case extension.Id.Equal(firmwareOID):
			var fw []byte
			if _, err := asn1.Unmarshal(extension.Value, &fw); err != nil {
				return nil, fmt.Errorf("parse firmware: %w", err)
			}
			parsed.Device.Firmware = fmt.Sprintf("%v.%v.%v", fw[0], fw[1], fw[2])

		case extension.Id.Equal(serialOID):
			var serial int
			if _, err := asn1.Unmarshal(extension.Value, &serial); err != nil {
				return nil, fmt.Errorf("parse serial: %w", err)
			}
			parsed.Device.Serial = serial

		case extension.Id.Equal(originOID):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(extension.Value, &bs); err != nil {
				return nil, fmt.Errorf("parse origin: %w", err)
			}
			origin := parseOrigins((uint8(bs.Bytes[0])))
			parsed.Key.Origin = origin

		case extension.Id.Equal(domainsOID):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(extension.Value, &bs); err != nil {
				return nil, fmt.Errorf("parse domains: %w", err)
			}
			domains := parseDomains(binary.BigEndian.Uint16(bs.Bytes))
			parsed.Key.Domains = domains

		case extension.Id.Equal(capabilitiesOID):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(extension.Value, &bs); err != nil {
				return nil, fmt.Errorf("parse capabilities: %w", err)
			}
			capabilities := parseCapabilities(binary.BigEndian.Uint64(bs.Bytes))
			parsed.Key.Capabilities = capabilities

		case extension.Id.Equal(objectIDOID):
			var objectID int
			if _, err := asn1.Unmarshal(extension.Value, &objectID); err != nil {
				return nil, fmt.Errorf("parse object id: %w", err)
			}
			parsed.Key.ID = objectID

		case extension.Id.Equal(labelOID):
			var label string
			if _, err := asn1.Unmarshal(extension.Value, &label); err != nil {
				return nil, fmt.Errorf("parse object label: %w", err)
			}
			parsed.Key.Label = label
		case extension.Id.Equal(fipsOID):
			var fips bool
			if _, err := asn1.Unmarshal(extension.Value, &fips); err != nil {
				return nil, fmt.Errorf("parse object fips: %w", err)
			}
			parsed.Key.FIPS = fips

		default:
			return nil, fmt.Errorf("unhandled extension oid: %v", extension.Id)
		}
	}

	return &parsed, nil
}

func parseDomains(input uint16) []int {
	var results []int
	for i := 0; i < 16; i++ {
		mask := uint16(1 << i)
		if mask&input != 0 {
			results = append(results, i+1)
		}
	}

	return results
}

func parseCapabilities(input uint64) []string {
	var results []string
	for i := 0; i < len(capabilities); i++ {
		mask := uint64(1 << i)
		if mask&input != 0 {
			results = append(results, capabilities[i])
		}
	}

	return results
}

func parseOrigins(input uint8) []string {
	var results []string
	for i := 0; i < len(origins); i++ {
		mask := uint8(1 << i)
		if mask&input != 0 {
			results = append(results, origins[i])
		}
	}
	return results
}
