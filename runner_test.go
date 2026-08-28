package main

import (
	"context"
	"errors"
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
		"--alias", "API_TOKEN=LEGACY_API_TOKEN",
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
	if !reflect.DeepEqual(parsed.aliases, []fieldAlias{{source: "API_TOKEN", target: "LEGACY_API_TOKEN"}}) {
		t.Fatalf("parseConfig returned the wrong aliases: %#v", parsed.aliases)
	}
}

func TestParseConfigRejectsUnsafeInput(t *testing.T) {
	tests := [][]string{
		{"--server", "http://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "item-name", "--field", "API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "BAD-NAME"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "API_TOKEN", "--field", "API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--alias", "MISSING_SEPARATOR"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--alias", "API_TOKEN=BAD-NAME"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--field", "API_TOKEN", "--alias", "OTHER=API_TOKEN"},
		{"--server", "https://vault.example.com", "--item-id", "123e4567-e89b-12d3-a456-426614174000", "--alias", "ONE=OUTPUT", "--alias", "TWO=OUTPUT"},
	}
	for _, arguments := range tests {
		if _, err := parseConfig(arguments); err == nil {
			t.Fatalf("parseConfig accepted unsafe input: %#v", arguments)
		}
	}
}

func TestBuildOutputFields(t *testing.T) {
	selected := []secretField{
		{name: "DB_PASSWORD", value: "database-secret"},
		{name: "SMTP_PASSWORD", value: "mail-secret"},
	}
	fields, err := buildOutputFields(
		selected,
		[]string{"DB_PASSWORD"},
		[]fieldAlias{
			{source: "DB_PASSWORD", target: "MYSQL_PASSWORD"},
			{source: "SMTP_PASSWORD", target: "MAIL_PASSWORD"},
		},
	)
	if err != nil {
		t.Fatalf("buildOutputFields returned an error: %v", err)
	}
	want := []secretField{
		{name: "DB_PASSWORD", value: "database-secret"},
		{name: "MYSQL_PASSWORD", value: "database-secret"},
		{name: "MAIL_PASSWORD", value: "mail-secret"},
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("buildOutputFields returned %#v", fields)
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

func TestEncodeComposeEnvironment(t *testing.T) {
	content, err := encodeComposeEnvironment([]secretField{{name: "API_TOKEN", value: `a $value with "quotes" and \slashes\`}})
	if err != nil {
		t.Fatalf("encodeComposeEnvironment returned an error: %v", err)
	}
	if string(content) != "API_TOKEN=\"a \\$value with \\\"quotes\\\" and \\\\slashes\\\\\"\n" {
		t.Fatalf("encodeComposeEnvironment returned %q", content)
	}
	if _, err := encodeComposeEnvironment([]secretField{{name: "API_TOKEN", value: "line1\nline2"}}); err == nil {
		t.Fatal("encodeComposeEnvironment accepted a multiline value")
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

func TestRunWritesSelectedVaultFields(t *testing.T) {
	paths := testRuntimePaths(t)
	commands := &fakeCommandRunner{
		responses: map[string][]byte{
			"unlock": []byte("session-token\n"),
			"get":    []byte(`{"fields":[{"name":"API_TOKEN","value":"secret-value","type":1},{"name":"IGNORED","value":"not-selected","type":1}]}`),
		},
	}
	configuration := config{
		server:     "https://vault.example.com",
		itemID:     "123e4567-e89b-12d3-a456-426614174000",
		fieldNames: []string{"API_TOKEN"},
		aliases:    []fieldAlias{{source: "API_TOKEN", target: "LEGACY_API_TOKEN"}},
	}

	err := runForUID(context.Background(), configuration, commands, paths, os.Geteuid(), os.Geteuid())
	if err != nil {
		t.Fatalf("runForUID returned an error: %v", err)
	}
	content, err := os.ReadFile(paths.output)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "API_TOKEN=\"secret-value\"\nLEGACY_API_TOKEN=\"secret-value\"\n" {
		t.Fatalf("runForUID wrote %q", content)
	}
	wantCalls := [][]string{
		{"config", "server", "https://vault.example.com"},
		{"login", "--apikey", "--quiet"},
		{"unlock", "--passwordfile", paths.masterPassword, "--raw"},
		{"sync"},
		{"get", "item", "123e4567-e89b-12d3-a456-426614174000"},
		{"lock"},
		{"logout"},
	}
	if !reflect.DeepEqual(commands.calls, wantCalls) {
		t.Fatalf("runForUID called %#v", commands.calls)
	}
	for index, arguments := range commands.calls {
		if strings.Contains(strings.Join(arguments, "\n"), "secret-value") {
			t.Fatalf("call %d included a vault secret in its arguments", index)
		}
	}
}

func TestRunReportsBitwardenCommandFailures(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantError  string
		wantLogout bool
	}{
		{name: "config", command: "config", wantError: "could not configure the Bitwarden server"},
		{name: "login", command: "login", wantError: "could not log in to Bitwarden"},
		{name: "unlock", command: "unlock", wantError: "could not unlock the Bitwarden vault", wantLogout: true},
		{name: "sync", command: "sync", wantError: "could not sync the Bitwarden vault", wantLogout: true},
		{name: "get", command: "get", wantError: "could not read the Bitwarden item", wantLogout: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := testRuntimePaths(t)
			commands := &fakeCommandRunner{
				responses: map[string][]byte{"unlock": []byte("session-token")},
				failures:  map[string]error{test.command: errors.New("command failed")},
			}
			configuration := config{
				server:     "https://vault.example.com",
				itemID:     "123e4567-e89b-12d3-a456-426614174000",
				fieldNames: []string{"API_TOKEN"},
			}

			err := runForUID(context.Background(), configuration, commands, paths, os.Geteuid(), os.Geteuid())
			if err == nil || err.Error() != test.wantError {
				t.Fatalf("runForUID returned %v", err)
			}
			calledLogout := false
			for _, call := range commands.calls {
				if len(call) == 1 && call[0] == "logout" {
					calledLogout = true
				}
			}
			if calledLogout != test.wantLogout {
				t.Fatalf("logout called: %t, want %t", calledLogout, test.wantLogout)
			}
		})
	}
}

func testRuntimePaths(t *testing.T) runtimePaths {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	clientEnvironment := filepath.Join(directory, "client.env")
	masterPassword := filepath.Join(directory, "master-password")
	if err := os.WriteFile(clientEnvironment, []byte("BW_CLIENTID=user.id\nBW_CLIENTSECRET=client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(masterPassword, []byte("master-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return runtimePaths{
		credentialsDirectory: directory,
		clientEnvironment:    clientEnvironment,
		masterPassword:       masterPassword,
		output:               filepath.Join(t.TempDir(), ".env.runtime"),
	}
}

type fakeCommandRunner struct {
	calls     [][]string
	responses map[string][]byte
	failures  map[string]error
}

func (runner *fakeCommandRunner) Run(_ context.Context, arguments []string, _ []string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string(nil), arguments...))
	command := arguments[0]
	if err := runner.failures[command]; err != nil {
		return nil, err
	}
	return runner.responses[command], nil
}
