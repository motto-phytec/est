package hsmca

import (
	"encoding/json"
	"io/ioutil"
	"time"
)

// config contains the EST server configuration.
type config struct {
	Template *templateConfig `json:"template_cert,omitempty"`
}

type templateConfig struct {
	SerialNumber        int       `json:"serial_number,omitempty"`
	NotBefore           time.Time `json:"not_before,omitempty"`
	NotAfter            time.Time `json:"not_After,omitempty"`
	CertificateDuration int       `json:"certificate_duration,omitempty"`
	IsCA                bool      `json:"is_ca"`
	KeyUsage            int       `json:"key_usage"`
	ExtKeyUsage         []string  `json:"extkey_usage,omitempty"`
}

// configuration file.
func configFromFile(filename string) (*config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

const sample = `{
	"template_cert": {
        "serial_number": "Number to start",
        "not_before": "start time"
		"not_After": "end time"
		"certificate_duration": "days"
		"is_ca": "false"
		"key_usage": "x509.KeyUsageDigitalSignature,"
		"extkey_usage": "[
			"x509.ExtKeyUsageServerAuth", 
			"x509.ExtKeyUsageClientAuth",
    },
}`
