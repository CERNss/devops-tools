package dotenv

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("load %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: missing '='", path, lineNo)
		}

		key = strings.TrimSpace(key)
		if !validKey(key) {
			return fmt.Errorf("%s:%d: invalid key %q", path, lineNo, key)
		}

		parsedValue, err := parseValue(value)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, parsedValue); err != nil {
				return fmt.Errorf("%s:%d: set %s: %w", path, lineNo, key, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	return nil
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func parseValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value, nil
	}

	quote := value[0]
	if quote != '"' && quote != '\'' {
		return value, nil
	}
	if value[len(value)-1] != quote {
		return "", errors.New("unterminated quoted value")
	}
	if quote == '\'' {
		return value[1 : len(value)-1], nil
	}

	return strconv.Unquote(value)
}
