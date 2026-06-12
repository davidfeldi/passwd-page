package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/davidfeldi/passwd-page/internal/client"
	"github.com/davidfeldi/passwd-page/pkg/crypto"
)

var version = "dev"

const usageText = `passwd — zero-knowledge ephemeral secret sharing

Usage:
  passwd <command> [options]

Commands:
  create    Encrypt a secret and upload it, printing a one-time link
  get       Fetch and decrypt a secret from a passwd.page link
  version   Print the client version
  help      Show this help (also: -h, --help)

Run "passwd <command> --help" for command-specific options.

Environment:
  PASSWD_SERVER   Server URL (default: https://passwd.page)

Examples:
  passwd create "my secret"
  echo "$API_KEY" | passwd create --type api_key --ttl 5m
  passwd create --file .env --type env_file
  passwd get "https://passwd.page/s/abc123#key"
`

const createUsageText = `passwd create — encrypt a secret and upload it, printing a one-time link

Usage:
  passwd create [secret] [options]
  echo "secret" | passwd create [options]

The secret is read from (in order): a positional argument, --file, or stdin.
Encryption happens locally; the server never sees the key or plaintext.

Options:
  -t, --ttl <dur>     Time to live: 5m, 15m, 1h, 24h, 7d, 30d (default: 24h)
      --type <type>   Secret type: text, file, postgres_url, api_key, ssh_key,
                      env_file, jwt, oauth_token (default: text)
  -f, --file <path>   Read the secret from a file (max 1 MiB)
  -b, --burn          Burn after reading — destroy on first view (default: on)
      --no-burn       Keep readable until it expires
  -s, --server <url>  Override the server URL (default: $PASSWD_SERVER)
  -h, --help          Show this help

Examples:
  passwd create "sk_live_..." --type api_key --ttl 5m
  passwd create --file ./creds.txt
  echo "$DATABASE_URL" | passwd create --type postgres_url --no-burn
`

const getUsageText = `passwd get — fetch and decrypt a secret from a passwd.page link

Usage:
  passwd get <url> [options]

The decryption key is read from the URL fragment (after #) and never sent to
the server. For non-text secrets a "# type: <type>" hint is printed to stderr,
so plain redirection (passwd get ... > file) stays clean.

Options:
  -s, --server <url>  Override the server URL (default: derived from the link)
  -h, --help          Show this help

Examples:
  passwd get "https://passwd.page/s/abc123#kG7..."
  passwd get "https://passwd.page/s/abc123#kG7..." > secret.txt
`

func isHelpFlag(s string) bool {
	return s == "-h" || s == "--help" || s == "help"
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usageText)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return nil
	case "version", "-v", "--version":
		fmt.Println(version)
		return nil
	case "create":
		return runCreate(args[1:])
	case "get":
		return runGet(args[1:])
	default:
		return fmt.Errorf("unknown command: %s\nrun \"passwd help\" for usage", args[0])
	}
}

// allowedCLITypes lists the secret-type values accepted by `passwd create`.
// Kept in sync with internal/server/handlers.go.
var allowedCLITypes = map[string]struct{}{
	"text":         {},
	"file":         {},
	"postgres_url": {},
	"api_key":      {},
	"ssh_key":      {},
	"env_file":     {},
	"jwt":          {},
	"oauth_token":  {},
}

func runCreate(args []string) error {
	var (
		ttl        = "24h"
		burn       = true
		serverURL  = ""
		filePath   = ""
		secret     = ""
		secretType = "text"
	)

	// Parse flags manually
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			fmt.Print(createUsageText)
			return nil
		case "--ttl", "-t":
			i++
			if i >= len(args) {
				return fmt.Errorf("--ttl requires a value")
			}
			ttl = args[i]
		case "--burn", "-b":
			burn = true
		case "--no-burn":
			burn = false
		case "--server", "-s":
			i++
			if i >= len(args) {
				return fmt.Errorf("--server requires a value")
			}
			serverURL = args[i]
		case "--file", "-f":
			i++
			if i >= len(args) {
				return fmt.Errorf("--file requires a value")
			}
			filePath = args[i]
		case "--type":
			i++
			if i >= len(args) {
				return fmt.Errorf("--type requires a value")
			}
			secretType = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s (run \"passwd create --help\")", args[i])
			}
			positional = append(positional, args[i])
		}
	}

	// Validate TTL
	switch ttl {
	case "5m", "15m", "1h", "24h", "7d", "30d":
	default:
		return fmt.Errorf("invalid --ttl value %q (options: 5m, 15m, 1h, 24h, 7d, 30d)", ttl)
	}

	// Validate --type
	if _, ok := allowedCLITypes[secretType]; !ok {
		return fmt.Errorf("invalid --type value %q (options: text, file, postgres_url, api_key, ssh_key, env_file, jwt, oauth_token)", secretType)
	}

	// Read secret from: positional arg, --file, or stdin
	switch {
	case len(positional) > 0:
		fmt.Fprintf(os.Stderr, "warning: secret passed as argument is visible in process listings; prefer stdin or --file\n")
		secret = strings.Join(positional, " ")
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}
		secret = string(data)
	default:
		// Check if stdin has data
		stat, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("checking stdin: %w", err)
		}
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			secret = string(data)
		} else {
			return fmt.Errorf("no secret provided — pass it as an argument, use --file <path>, or pipe to stdin (run \"passwd create --help\")")
		}
	}

	if secret == "" {
		return fmt.Errorf("secret is empty")
	}

	// Encrypt
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}

	ciphertext, err := crypto.Encrypt([]byte(secret), key)
	if err != nil {
		return err
	}

	// Upload
	ctx := context.Background()
	c := client.NewClient(serverURL)
	id, _, err := c.CreateSecretWithType(ctx, ciphertext, ttl, burn, secretType)
	if err != nil {
		return err
	}

	// Build URL
	base := serverURL
	if base == "" {
		base = os.Getenv("PASSWD_SERVER")
	}
	if base == "" {
		base = "https://passwd.page"
	}
	keyB64 := crypto.KeyToBase64url(key)
	fmt.Printf("%s/s/%s#%s\n", strings.TrimRight(base, "/"), id, keyB64)
	return nil
}

func runGet(args []string) error {
	var serverOverride string

	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			fmt.Print(getUsageText)
			return nil
		case "--server", "-s":
			i++
			if i >= len(args) {
				return fmt.Errorf("--server requires a value")
			}
			serverOverride = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s (run \"passwd get --help\")", args[i])
			}
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 1 {
		return fmt.Errorf("usage: passwd get <url>  (run \"passwd get --help\")")
	}

	rawURL := positional[0]

	// Parse URL to extract server base, secret ID, and key fragment
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Extract key from fragment (after #)
	keyFragment := parsed.Fragment
	if keyFragment == "" {
		return fmt.Errorf("URL missing key fragment (the part after #)")
	}

	// Extract ID from path: /s/{id}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] != "s" {
		return fmt.Errorf("invalid URL path: expected /s/{id}")
	}
	id := pathParts[1]

	// Determine server base
	serverBase := serverOverride
	if serverBase == "" {
		serverBase = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}

	// Decode key
	key, err := crypto.Base64urlToKey(keyFragment)
	if err != nil {
		return err
	}

	// Fetch
	ctx := context.Background()
	c := client.NewClient(serverBase)
	ciphertext, _, secretType, err := c.GetSecretWithType(ctx, id)
	if err != nil {
		return err
	}

	// Decrypt
	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return err
	}

	// Emit an informational comment line prefix so agents/tools know the
	// stored schema. It's deliberately a `#`-prefixed line on stderr so
	// plain `passwd get ... > file` piping stays unaffected.
	if secretType != "" && secretType != "text" {
		fmt.Fprintf(os.Stderr, "# type: %s\n", secretType)
	}

	fmt.Print(string(plaintext))
	return nil
}
