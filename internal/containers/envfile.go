package containers

import (
	"fmt"
	"os"
	"strings"
)

// EnvFile reads an environment file — one KEY=VALUE per line, with
// blank lines and #-comments ignored and a matching pair of quotes
// around the value stripped — and returns the entries in KEY=VALUE
// form, for the runtimes' --env flags.
func EnvFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envs []string
	for lineno, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.ContainsAny(key, " \t\"'") {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE, got %q", path, lineno+1, line)
		}
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		envs = append(envs, key+"="+value)
	}
	return envs, nil
}
