package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	bitwardenBinary = "/usr/local/bin/bw"
	hiddenFieldType = 1
	runnerUID       = 1000
)

var (
	errHelpRequested = errors.New("help requested")
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fieldNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type config struct {
	server     string
	itemID     string
	fieldNames []string
}

type runtimePaths struct {
	credentialsDirectory string
	clientEnvironment     string
	masterPassword        string
	output                string
}

type credentials struct {
	clientID     string
	clientSecret string
}

type secretField struct {
	name  string
	value string
}

type vaultItem struct {
	Fields []vaultField `json:"fields"`
}

type vaultField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

type commandRunner interface {
	Run(context.Context, []string, []string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, arguments []string, environment []string) ([]byte, error) {
	command := exec.CommandContext(ctx, bitwardenBinary, arguments...)
	command.Env = environment
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("Bitwarden CLI command failed")
	}
	return stdout.Bytes(), nil
}

func defaultRuntimePaths() runtimePaths {
	return runtimePaths{
		credentialsDirectory: "/run/bwcreds",
		clientEnvironment:     "/run/bwcreds/client.env",
		masterPassword:        "/run/bwcreds/master-password",
		output:                ".env.runtime",
	}
}

func parseConfig(arguments []string) (config, error) {
	var parsed config
	var fields stringList
	flags := flag.NewFlagSet("arcane-bw-runner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.server, "server", "", "Vaultwarden server URL")
	flags.StringVar(&parsed.itemID, "item-id", "", "Bitwarden item UUID")
	flags.Var(&fields, "field", "hidden custom field to export")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config{}, errHelpRequested
		}
		return config{}, errors.New("invalid arguments")
	}
	if flags.NArg() != 0 {
		return config{}, errors.New("positional arguments are not supported")
	}
	if err := checkServer(parsed.server); err != nil {
		return config{}, err
	}
	if !uuidPattern.MatchString(parsed.itemID) {
		return config{}, errors.New("--item-id must be a lowercase UUID")
	}
	if len(fields) == 0 {
		return config{}, errors.New("at least one --field is needed")
	}
	seen := make(map[string]struct{}, len(fields))
	for _, name := range fields {
		if !fieldNamePattern.MatchString(name) {
			return config{}, fmt.Errorf("invalid field name %q", name)
		}
		if _, exists := seen[name]; exists {
			return config{}, fmt.Errorf("duplicate field name %q", name)
		}
		seen[name] = struct{}{}
	}
	parsed.fieldNames = append([]string(nil), fields...)
	return parsed, nil
}

func checkServer(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("--server must be an HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("--server must not contain credentials, a query, or a fragment")
	}
	return nil
}

func run(ctx context.Context, config config, commands commandRunner, paths runtimePaths, uid int) error {
	if uid != runnerUID {
		return fmt.Errorf("runner must use UID %d", runnerUID)
	}
	if err := checkSecureDirectory(paths.credentialsDirectory, uid); err != nil {
		return err
	}
	clientEnvironment, err := readSecureFile(paths.clientEnvironment, uid)
	if err != nil {
		return err
	}
	if _, err := readSecureFile(paths.masterPassword, uid); err != nil {
		return err
	}
	credentials, err := parseClientEnvironment(clientEnvironment)
	if err != nil {
		return err
	}

	appDataDirectory, err := os.MkdirTemp("", "arcane-bw-")
	if err != nil {
		return errors.New("could not create the Bitwarden CLI data directory")
	}
	defer os.RemoveAll(appDataDirectory)
	if err := os.Chmod(appDataDirectory, 0o700); err != nil {
		return errors.New("could not secure the Bitwarden CLI data directory")
	}

	environment := commandEnvironment(credentials, appDataDirectory, "")
	if _, err := commands.Run(ctx, []string{"config", "server", config.server}, environment); err != nil {
		return errors.New("could not configure the Bitwarden server")
	}
	if _, err := commands.Run(ctx, []string{"login", "--apikey", "--quiet"}, environment); err != nil {
		return errors.New("could not log in to Bitwarden")
	}
	cleanupEnvironment := environment
	cleanupSession := ""
	defer func() {
		cleanupBitwarden(commands, cleanupEnvironment, cleanupSession)
	}()

	sessionBytes, err := commands.Run(ctx, []string{"unlock", "--passwordfile", paths.masterPassword, "--raw"}, environment)
	if err != nil {
		return errors.New("could not unlock the Bitwarden vault")
	}
	session := strings.TrimSpace(string(sessionBytes))
	if session == "" || strings.ContainsAny(session, "\r\n\x00") {
		return errors.New("Bitwarden returned an invalid session")
	}
	sessionEnvironment := commandEnvironment(credentials, appDataDirectory, session)
	cleanupEnvironment = sessionEnvironment
	cleanupSession = session

	if _, err := commands.Run(ctx, []string{"sync"}, sessionEnvironment); err != nil {
		return errors.New("could not sync the Bitwarden vault")
	}
	itemJSON, err := commands.Run(ctx, []string{"get", "item", config.itemID}, sessionEnvironment)
	if err != nil {
		return errors.New("could not read the Bitwarden item")
	}
	fields, err := selectSecretFields(itemJSON, config.fieldNames)
	if err != nil {
		return err
	}
	content, err := encodeRawEnvironment(fields)
	if err != nil {
		return err
	}
	if err := writeRuntimeEnvironment(paths.output, content); err != nil {
		return err
	}
	return nil
}

func checkSecureDirectory(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("credentials directory is not accessible")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credentials path is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("credentials directory must use mode 0700")
	}
	if err := checkOwner(info, uid); err != nil {
		return errors.New("credentials directory has the wrong owner")
	}
	return nil
}

func readSecureFile(path string, uid int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("credential file is not accessible")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential path is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, errors.New("credential file must use mode 0600")
	}
	if err := checkOwner(info, uid); err != nil {
		return nil, errors.New("credential file has the wrong owner")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("could not read a credential file")
	}
	return content, nil
}

func checkOwner(info os.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return errors.New("owner mismatch")
	}
	return nil
}

func parseClientEnvironment(content []byte) (credentials, error) {
	if !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return credentials{}, errors.New("client.env contains invalid text")
	}
	values := make(map[string]string, 2)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || (parts[0] != "BW_CLIENTID" && parts[0] != "BW_CLIENTSECRET") {
			return credentials{}, errors.New("client.env must contain only BW_CLIENTID and BW_CLIENTSECRET")
		}
		if _, exists := values[parts[0]]; exists {
			return credentials{}, errors.New("client.env contains a duplicate key")
		}
		if parts[1] == "" || parts[1] != strings.TrimSpace(parts[1]) {
			return credentials{}, errors.New("client.env contains an empty or padded value")
		}
		values[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return credentials{}, errors.New("could not parse client.env")
	}
	if len(values) != 2 {
		return credentials{}, errors.New("client.env must contain BW_CLIENTID and BW_CLIENTSECRET")
	}
	return credentials{clientID: values["BW_CLIENTID"], clientSecret: values["BW_CLIENTSECRET"]}, nil
}

func commandEnvironment(credentials credentials, appDataDirectory string, session string) []string {
	blocked := map[string]struct{}{
		"BITWARDENCLI_APPDATA_DIR": {},
		"BW_CLIENTID":              {},
		"BW_CLIENTSECRET":          {},
		"BW_PASSWORD":              {},
		"BW_SESSION":               {},
	}
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, exists := blocked[key]; !exists {
			environment = append(environment, entry)
		}
	}
	environment = append(environment,
		"BITWARDENCLI_APPDATA_DIR="+appDataDirectory,
		"BW_CLIENTID="+credentials.clientID,
		"BW_CLIENTSECRET="+credentials.clientSecret,
	)
	if session != "" {
		environment = append(environment, "BW_SESSION="+session)
	}
	return environment
}

func cleanupBitwarden(commands commandRunner, environment []string, session string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if session != "" {
		_, _ = commands.Run(ctx, []string{"lock"}, environment)
	}
	_, _ = commands.Run(ctx, []string{"logout"}, environment)
}

func selectSecretFields(itemJSON []byte, requested []string) ([]secretField, error) {
	var item vaultItem
	if err := json.Unmarshal(itemJSON, &item); err != nil {
		return nil, errors.New("Bitwarden returned invalid item data")
	}
	requestedSet := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		requestedSet[name] = struct{}{}
	}
	found := make(map[string]vaultField, len(requested))
	for _, field := range item.Fields {
		if _, wanted := requestedSet[field.Name]; !wanted {
			continue
		}
		if _, duplicate := found[field.Name]; duplicate {
			return nil, fmt.Errorf("item contains duplicate field %q", field.Name)
		}
		found[field.Name] = field
	}
	result := make([]secretField, 0, len(requested))
	for _, name := range requested {
		field, exists := found[name]
		if !exists {
			return nil, fmt.Errorf("item does not contain field %q", name)
		}
		if field.Type != hiddenFieldType {
			return nil, fmt.Errorf("field %q is not hidden", name)
		}
		if field.Value == "" {
			return nil, fmt.Errorf("field %q is empty", name)
		}
		result = append(result, secretField{name: name, value: field.Value})
	}
	return result, nil
}

func encodeRawEnvironment(fields []secretField) ([]byte, error) {
	var output strings.Builder
	for _, field := range fields {
		if !fieldNamePattern.MatchString(field.name) {
			return nil, errors.New("field name cannot be written to an env file")
		}
		if strings.ContainsAny(field.value, "\r\n\x00") {
			return nil, fmt.Errorf("field %q contains a line break or null byte", field.name)
		}
		output.WriteString(field.name)
		output.WriteByte('=')
		output.WriteString(field.value)
		output.WriteByte('\n')
	}
	return []byte(output.String()), nil
}

func writeRuntimeEnvironment(path string, content []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New(".env.runtime must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not check .env.runtime")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".env.runtime.tmp-")
	if err != nil {
		return errors.New("could not create .env.runtime")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("could not secure .env.runtime")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("could not write .env.runtime")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("could not sync .env.runtime")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("could not close .env.runtime")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("could not replace .env.runtime")
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("could not open the project directory")
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return errors.New("could not sync the project directory")
	}
	return nil
}
