package inputsanitizer_test

import (
	"encoding/json"
	"fmt"
	"testing"

	inputsanitizer "github.com/di-graph/input-sanitizer"
	"github.com/stretchr/testify/assert"
)

const sensitiveJSON = `{
	"someitem": [],
	"password": "TEST PASSWORD",
	"a1": 123,
	"paTESTssword": "test",
	"changes": {
		"db_auth_key": "TEST KEY",
		"username":"TEST USERNAME",
		"normal_change": "hello"
	}
}`

const specificSensitiveJSON = `{
	"testing": "foobar",
	"arrayKey": [],
	"changes": {
		"normal_change": "hello",
		"%s":"barfoo"
	}
}`

func TestSanitizeJSON(t *testing.T) {
	jsonBytes := []byte(sensitiveJSON)
	sanitizedValues, err := inputsanitizer.SanitizeValuesByKey(jsonBytes)
	var results map[string]interface{}
	json.Unmarshal(sanitizedValues, &results)
	assert.Nil(t, err)
	assert.Equal(t, "REDACTED", results["password"])
	assert.Equal(t, "test", results["paTESTssword"])
	assert.Equal(t, float64(123), results["a1"])
	changeMap := results["changes"].(map[string]interface{})
	assert.Equal(t, changeMap["username"], "REDACTED")
	assert.Equal(t, changeMap["db_auth_key"], "REDACTED")
	assert.Equal(t, changeMap["normal_change"], "hello")
}
func TestSpecificSensitiveKey(t *testing.T) {
	cases := []string{
		"account_key",
		"api_key",
		"auth_123_key",
		"client-token-key",
		"database_key",
		"database_master_pass",
		"db_key",
		"private_access_key",
		"service_key",
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			jsonBytes := []byte(fmt.Sprintf(specificSensitiveJSON, v))
			sanitizedValues, err := inputsanitizer.SanitizeValuesByKey(jsonBytes)
			var results map[string]interface{}
			json.Unmarshal(sanitizedValues, &results)
			assert.Nil(t, err)
			assert.Equal(t, "foobar", results["testing"])
			changeMap := results["changes"].(map[string]interface{})
			assert.Equal(t, "REDACTED", changeMap[v])
			assert.Equal(t, "hello", changeMap["normal_change"])
		})
	}
}

const secretObject = `{
"template": [
	{
	  "containers": [
		{
		  "args": null,
		  "command": null,
		  "env": [],
		  "image": "gcr.io/digraph-2021/cloudquery-cloudrun@sha256:latest",
		  "liveness_probe": [],
		  "name": null,
		  "ports": [],
		  "volume_mounts": [
			{
			  "mount_path": "/secrets",
			  "name": "secrets"
			}
		  ],
		  "working_dir": null
		}
	  ],
	  "encryption_key": null,
	  "max_retries": 3,
	  "volumes": [
		{
		  "cloud_sql_instance": [],
		  "name": "secrets",
		  "secret": [
			{
			  "default_mode": null,
			  "items": [
				{
				  "mode": 256,
				  "path": "config.yml",
				  "version": "1"
				}
			  ],
			  "secret": "cloudquery_config_src_gcloud_dst_gcs"
			}
		  ]
		}
	  ],
	  "vpc_access": []
	}
  ]
}`

func TestSanitizeSecrets(t *testing.T) {
	jsonBytes := []byte(secretObject)
	sanitizedValues, err := inputsanitizer.SanitizeValuesByKey(jsonBytes)
	var results map[string]interface{}
	json.Unmarshal(sanitizedValues, &results)
	assert.Nil(t, err)
	template := results["template"].([]interface{})[0].(map[string]interface{})
	volumes := template["volumes"].([]interface{})[0].(map[string]interface{})
	secret := volumes["secret"].(string)
	assert.Equal(t, "REDACTED", secret)
}
