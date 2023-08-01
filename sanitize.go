package inputsanitizer

import (
	"encoding/json"
	"fmt"
	"regexp"
)

const sanitize_replacement_string string = "REDACTED"

var preCompiledRegExpList []*regexp.Regexp

func init() {
	preCompiledRegExpList = []*regexp.Regexp{
		constructSensitiveRegExp(`account[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`api[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`auth[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`azurerm-account-key`),
		constructSensitiveRegExp(`client[_|/-](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`contrasena`),
		constructSensitiveRegExp(`database[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`database[_|/-|\s](.[\w\s_/-]+)*pass`),
		constructSensitiveRegExp(`database[_|/-|\s](.[\w\s_/-]+)*password`),
		constructSensitiveRegExp(`db[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`db[_|/-|\s](.[\w\s_/-]+)*pass`),
		constructSensitiveRegExp(`db[_|/-|\s](.[\w\s_/-]+)*password`),
		constructSensitiveRegExp(`fetch-tfstate-headers`),
		constructSensitiveRegExp(`key[_|/-|\s](.[\w\s_/-]+)*pass`),
		constructSensitiveRegExp(`key[_|/-|\s](.[\w\s_/-]+)*password`),
		constructSensitiveRegExp(`passwd`),
		constructSensitiveRegExp(`password`),
		constructSensitiveRegExp(`priv[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`private[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`pwd`),
		constructSensitiveRegExp(`secret`),
		constructSensitiveRegExp(`service[_|/-|\s](.[\w\s_/-]+)*key`),
		constructSensitiveRegExp(`tfc-token`),
		constructSensitiveRegExp(`username`),
	}
}

func constructSensitiveRegExp(filter string) *regexp.Regexp {
	filterString := fmt.Sprintf(`(?i)\b%s\b`, filter)
	return regexp.MustCompile(filterString)
}

func SanitizeValuesByKey(content []byte) ([]byte, error) {
	sanitizedJSON, err := redactJSON(content)
	if err != nil {
		return nil, err
	}
	return []byte(sanitizedJSON), nil
}

func redactJSON(inputJSON []byte) (string, error) {
	var data interface{}
	err := json.Unmarshal(inputJSON, &data)
	if err != nil {
		return "", err
	}

	redactSensitiveData(data)

	redactedJSON, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(redactedJSON), nil
}

func redactSensitiveData(data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if shouldRedact(key) {
				v[key] = sanitize_replacement_string
			} else {
				redactSensitiveData(val)
			}
		}
	case []interface{}:
		for _, val := range v {
			redactSensitiveData(val)
		}
	}
}

func shouldRedact(key string) bool {
	for _, regex := range preCompiledRegExpList {
		if regex.MatchString(key) {
			return true
		}
	}
	return false
}
