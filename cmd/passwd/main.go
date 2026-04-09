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

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: passwd <create|get|version> [options]")
	}

	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "create":
		return runCreate(args[1:])
	case "get":
		return runGet(args[1:])
	default:
		return fmt.Errorf("unknown command: %s\nusage: passwd <create|get|version> [options]", args[0])
	}
}

func runCreate(args []string) error {
	var (
		ttl       = "24h"
		burn      = true
		serverURL = ""
		filePath  = ""
		secret    = ""
	)

	// Parse flags manually
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
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
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s", args[i])
			}
			positional = append(positional, args[i])
		}
	}

	// Validate TTL
	switch ttl {
	case "1h", "24h", "7d":
	default:
		return fmt.Errorf("invalid --ttl value %q (options: 1h, 24h, 7d)", ttl)
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
			return fmt.Errorf("no secret provided (pass as argument, --file, or pipe to stdin)")
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
	id, _, err := c.CreateSecret(ctx, ciphertext, ttl, burn)
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
		case "--server", "-s":
			i++
			if i >= len(args) {
				return fmt.Errorf("--server requires a value")
			}
			serverOverride = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s", args[i])
			}
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 1 {
		return fmt.Errorf("usage: passwd get <url>")
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
	ciphertext, _, err := c.GetSecret(ctx, id)
	if err != nil {
		return err
	}

	// Decrypt
	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return err
	}

	fmt.Print(string(plaintext))
	return nil
}
