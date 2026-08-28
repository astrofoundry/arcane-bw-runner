package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	parsed, err := parseConfig([]string{
		"--server", "https://vault.example.com",
		"--item-id", "123e4567-e89b-12d3-a456-426614174000",
		"--field", "API_TOKEN",
		"--field", "DATABASE_URL",
	})
	if err != nil {
		t.Fatalf("parseConfig returned an error: %v", err)
	}
	if parsed.server != "https://vault.example.com" || parsed.itemID != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("parseConfig returned the wrong config: %#v", parsed)
	}
	if !reflect.DeepEqual(parsed.fieldNames, []string{"API_TOKEN", "DATABASE_URL"}) {
		t.Fatalf("parseConfig returned the wrong fields: %#v", parsed.fieldNames)
	}
}

func TestParseConfigRejectsUnsafeInput(t *testing.T) {
	tests := [][]string{
		{"--server", "http://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "item-name", "--field", "API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "BAD-NAME"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "API_TOKEN", "--field", "API_TOKEN"},
	}
	for _, arguments := range tests {
		if _, err := parseConfig(arguments); err == nil {
			t.Fatalf("parseConfig accepted unsafe input: %#v", arguments)
		}
	}
}

func TestParseClientEnvironment(t *testing.T) {
	parsed, err := parseClientEnvironment([]byte("BW_CLIENTID=user.id\nBW_CLIENTSECRET=secret=value\n"))
	if err != nil {
		t.Fatalf("parseClientEnvironment returned an error: %v", err)
	}
	if parsed.clientID != "user.id" || parsed.clientSecret != "secret=value" {
		t.Fatal("parseClientEnvironment returned the wrong credentials")
	}
}

func TestParseClientEnvironmentRejectsShellSyntax(t *testing.T) {
	inputs := []string{
		"export BW_CLIENTID=user.id\nBW_CLIENTSECRET=secret\n",
		"BW_CLIENTID=user.id\nBW_CLIENTSECRET=secret\nEXTRA=value\n",
		"BW_CLIENTID=user.id\nBW_CLIENTID=other\nBW_CLIENTSECRET=secret\n",
		"BW_CLIENTID=user.id\nBW_CLIENTSECRET= secret\n",
	}
	for _, input := range inputs {
		if _, err := parseClientEnvironment([]byte(input)); err == nil {
			t.Fatalf("parseClientEnvironment accepted %q", input)
		}
	}
}

func TestSecureCredentialPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "client.env")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSecureDirectory(directory, os.Geteuid()); err != nil {
		t.Fatalf("checkSecureDirectory returned an error: %v", err)
	}
	if _, err := readSecureFile(path, os.Geteuid()); err != nil {
		t.Fatalf("readSecureFile returned an error: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(path, os.Geteuid()); err == nil {
		t.Fatal("readSecureFile accepted mode 0640")
	}
}

func TestSelectSecretFields(t *testing.T) {
	item := []byte(`{"fields":[{"name":"API_TOKEN","value":"token","type":1},{"name":"VISIBLE","value":"public","type":0}]}`)
	fields, err := selectSecretFields(item, []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("selectSecretFields returned an error: %v", err)
	}
	if !reflect.DeepEqual(fields, []secretField{{name: "API_TOKEN", value: "token"}}) {
		t.Fatalf("selectSecretFields returned the wrong fields: %#v", fields)
	}
	if _, err := selectSecretFields(item, []string{"VISIBLE"}); err == nil {
		t.Fatal("selectSecretFields accepted a visible field")
	}
}

func TestSelectSecretFieldsRejectsDuplicate(t *testing.T) {
	item := []byte(`{"fields":[{"name":"API_TOKEN","value":"one","type":1},{"name":"API_TOKEN","value":"two","type":1}]}`)
	if _, err := selectSecretFields(item, []string{"API_TOKEN"}); err == nil {
		t.Fatal("selectSecretFields accepted a duplicate field")
	}
}

func TestEncodeRawEnvironment(t *testing.T) {
	content, err := encodeRawEnvironment([]secretField{{name: "API_TOKEN", value: "a $value with 'quotes'=and#hashes"}})
	if err != nil {
		t.Fatalf("encodeRawEnvironment returned an error: %v", err)
	}
	if string(content) != "API_TOKEN=a $value with 'quotes'=and#hashes\n" {
		t.Fatalf("encodeRawEnvironment returned %q", content)
	}
	if _, err := encodeRawEnvironment([]secretField{{name: "API_TOKEN", value: "line1\nline2"}}); err == nil {
		t.Fatal("encodeRawEnvironment accepted a multiline value")
	}
}

func TestWriteRuntimeEnvironment(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env.runtime")
	if err := os.WriteFile(path, []byte("OLD=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeEnvironment(path, []byte("NEW=value\n")); err != nil {
		t.Fatalf("writeRuntimeEnvironment returned an error: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "NEW=value\n" {
		t.Fatalf("writeRuntimeEnvironment wrote %q", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("writeRuntimeEnvironment used mode %04o", info.Mode().Perm())
	}
}

func TestCleanupBitwardenLocksAndLogsOut(t *testing.T) {
	commands := &fakeCommandRunner{}
	cleanupBitwarden(commands, nil, "session")
	want := [][]string{{"lock"}, {"logout"}}
	if !reflect.DeepEqual(commands.calls, want) {
		t.Fatalf("cleanupBitwarden called %#v", commands.calls)
	}
}

func TestCommandEnvironmentRemovesInheritedSecrets(t *testing.T) {
	t.Setenv("BW_CLIENTID", "inherited")
	t.Setenv("BW_CLIENTSECRET", "inherited")
	t.Setenv("BW_SESSION", "inherited")
	environment := commandEnvironment(credentials{clientID: "expected-id", clientSecret: "expected-secret"}, "/tmp/appdata", "expected-session")
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "BW_CLIENTID=inherited") || strings.Contains(joined, "BW_SESSION=inherited") {
		t.Fatal("commandEnvironment kept inherited credentials")
	}
	for _, expected := range []string{"BW_CLIENTID=expected-id", "BW_CLIENTSECRET=expected-secret", "BW_SESSION=expected-session"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("commandEnvironment did not contain %q", expected)
		}
	}
}

func TestRunRejectsWrongUID(t *testing.T) {
	err := run(context.Background(), config{}, &fakeCommandRunner{}, runtimePaths{}, runnerUID+1)
	if err == nil {
		t.Fatal("run accepted the wrong UID")
	}
}

type fakeCommandRunner struct {
	calls [][]string
}

func (runner *fakeCommandRunner) Run(_ context.Context, arguments []string, _ []string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string(nil), arguments...))
	return nil, nil
}
