package inputsanitizer

import (
	"fmt"
	"regexp"
)

const sanitize_replacement_string string = "REDACTED"

var sensitiveFieldNames = []string{
	`account[_|/-|\s](.[\w\s_/-]+)*key`,
	`api[_|/-|\s](.[\w\s_/-]+)*key`,
	`auth[_|/-|\s](.[\w\s_/-]+)*key`,
	`azurerm-account-key`,
	`client[_|/-](.[\w\s_/-]+)*key`,
	`contrasena`,
	`database[_|/-|\s](.[\w\s_/-]+)*key`,
	`database[_|/-|\s](.[\w\s_/-]+)*pass`,
	`database[_|/-|\s](.[\w\s_/-]+)*password`,
	`db[_|/-|\s](.[\w\s_/-]+)*key`,
	`db[_|/-|\s](.[\w\s_/-]+)*pass`,
	`db[_|/-|\s](.[\w\s_/-]+)*password`,
	`fetch-tfstate-headers`,
	`key[_|/-|\s](.[\w\s_/-]+)*pass`,
	`key[_|/-|\s](.[\w\s_/-]+)*password`,
	`passwd`,
	`password`,
	`priv[_|/-|\s](.[\w\s_/-]+)*key`,
	`private[_|/-|\s](.[\w\s_/-]+)*key`,
	`pwd`,
	`secret`,
	`service[_|/-|\s](.[\w\s_/-]+)*key`,
	`tfc-token`,
	`username`,
}

func SanitizeValuesByKey(content []byte) ([]byte, error) {
	for i := range sensitiveFieldNames {
		filter := sensitiveFieldNames[i]
		r := regexp.MustCompile(fmt.Sprintf(`(?:\"|\')(?P<key>(%s)+)(?:\"|\')(?:\:\s*)(?:\"|\')?(?P<value>[\w\s-\[\]]*)(?:\"|\')?`, filter))
		template := fmt.Sprintf("\"$key\":\"%s\"", sanitize_replacement_string)
		content = r.ReplaceAll(content, []byte(template))
	}
	return content, nil
}
