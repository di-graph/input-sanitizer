package inputsanitizer

import (
	"fmt"
	"regexp"
)

const sanitize_replacement_string string = "REDACTED"

var preCompiledRegExpList = []*regexp.Regexp{
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

func constructSensitiveRegExp(filter string) *regexp.Regexp {
	filterString := fmt.Sprintf(`(?:\"|\')(?P<key>(%s)+)(?:\"|\')(?:\:\s*)(?:\"|\')?(?P<value>[\w\s-\[\]]*)(?:\"|\')?`, filter)
	return regexp.MustCompile(filterString)
}

func SanitizeValuesByKey(content []byte) ([]byte, error) {
	for _, sensitiveRegExp := range preCompiledRegExpList {
		template := fmt.Sprintf("\"$key\":\"%s\"", sanitize_replacement_string)
		content = sensitiveRegExp.ReplaceAll(content, []byte(template))
	}
	return content, nil
}
