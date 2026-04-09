package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/davidfeldi/passwd-page/internal/client"
	"github.com/davidfeldi/passwd-page/pkg/crypto"
)

// JSON-RPC types

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP types

type serverInfo struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    caps       `json:"capabilities"`
	ServerInfo      nameVer    `json:"serverInfo"`
}

type caps struct {
	Tools *struct{} `json:"tools"`
}

type nameVer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema toolSchema `json:"inputSchema"`
}

type toolSchema struct {
	Type       string              `json:"type"`
	Properties map[string]property `json:"properties"`
	Required   []string            `json:"required"`
}

type property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Tool definitions

var tools = []tool{
	{
		Name:        "share_secret",
		Description: "Encrypt and share a secret via passwd.page. Returns a one-time URL.",
		InputSchema: toolSchema{
			Type: "object",
			Properties: map[string]property{
				"secret":          {Type: "string", Description: "The secret to share"},
				"ttl":             {Type: "string", Description: "Time to live: 1h, 24h, or 7d", Default: "24h"},
				"burn_after_read": {Type: "boolean", Description: "Destroy secret after first read", Default: true},
			},
			Required: []string{"secret"},
		},
	},
	{
		Name:        "share_file",
		Description: "Encrypt and share a file via passwd.page WITHOUT the agent seeing its contents. The file is read directly by the tool — its contents never enter the conversation context. Ideal for .env files, credentials, keys.",
		InputSchema: toolSchema{
			Type: "object",
			Properties: map[string]property{
				"path":            {Type: "string", Description: "Absolute path to the file to encrypt and share"},
				"ttl":             {Type: "string", Description: "Time to live: 1h, 24h, or 7d", Default: "24h"},
				"burn_after_read": {Type: "boolean", Description: "Destroy secret after first read", Default: true},
			},
			Required: []string{"path"},
		},
	},
	{
		Name:        "retrieve_secret",
		Description: "Retrieve and decrypt a secret from a passwd.page URL.",
		InputSchema: toolSchema{
			Type: "object",
			Properties: map[string]property{
				"url": {Type: "string", Description: "Full passwd.page URL including #key fragment"},
			},
			Required: []string{"url"},
		},
	},
}

func main() {
	log := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	apiClient := client.NewClient("")
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer for large secrets.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	log("passwd-mcp server started")

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			log("invalid JSON: %v", err)
			continue
		}

		// Notifications have no id — no response needed.
		if req.ID == nil {
			log("notification: %s", req.Method)
			continue
		}

		resp := handle(req, apiClient, log)
		resp.JSONRPC = "2.0"
		resp.ID = req.ID

		out, err := json.Marshal(resp)
		if err != nil {
			log("marshal error: %v", err)
			continue
		}
		fmt.Fprintf(os.Stdout, "%s\n", out)
	}

	if err := scanner.Err(); err != nil {
		log("stdin error: %v", err)
		os.Exit(1)
	}
}

func handle(req request, apiClient *client.Client, log func(string, ...any)) response {
	switch req.Method {
	case "initialize":
		return response{Result: serverInfo{
			ProtocolVersion: "2024-11-05",
			Capabilities:    caps{Tools: &struct{}{}},
			ServerInfo:      nameVer{Name: "passwd-mcp", Version: "1.0.0"},
		}}

	case "tools/list":
		return response{Result: struct {
			Tools []tool `json:"tools"`
		}{Tools: tools}}

	case "tools/call":
		return handleToolCall(req.Params, apiClient, log)

	default:
		return response{Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}
	}
}

func handleToolCall(params json.RawMessage, apiClient *client.Client, log func(string, ...any)) response {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return response{Error: &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}}
	}

	switch call.Name {
	case "share_secret":
		return shareSecret(call.Arguments, apiClient, log)
	case "share_file":
		return shareFile(call.Arguments, apiClient, log)
	case "retrieve_secret":
		return retrieveSecret(call.Arguments, apiClient, log)
	default:
		return response{Error: &rpcError{Code: -32602, Message: "unknown tool: " + call.Name}}
	}
}

func shareSecret(args json.RawMessage, apiClient *client.Client, log func(string, ...any)) response {
	var p struct {
		Secret       string `json:"secret"`
		TTL          string `json:"ttl"`
		BurnAfterRead *bool `json:"burn_after_read"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return toolError("invalid arguments: " + err.Error())
	}
	if p.Secret == "" {
		return toolError("secret is required")
	}
	if p.TTL == "" {
		p.TTL = "24h"
	}
	switch p.TTL {
	case "1h", "24h", "7d":
	default:
		return toolError("invalid ttl: must be 1h, 24h, or 7d")
	}
	burn := true
	if p.BurnAfterRead != nil {
		burn = *p.BurnAfterRead
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return toolError("generate key: " + err.Error())
	}

	ciphertext, err := crypto.Encrypt([]byte(p.Secret), key)
	if err != nil {
		return toolError("encrypt: " + err.Error())
	}

	ctx := context.Background()
	id, _, err := apiClient.CreateSecret(ctx, ciphertext, p.TTL, burn)
	if err != nil {
		return toolError("create secret: " + err.Error())
	}

	serverURL := os.Getenv("PASSWD_SERVER")
	if serverURL == "" {
		serverURL = "https://passwd.page"
	}

	secretURL := fmt.Sprintf("%s/s/%s#%s", serverURL, id, crypto.KeyToBase64url(key))
	log("shared secret: %s", id)

	result, _ := json.Marshal(map[string]string{"url": secretURL})
	return response{Result: toolResult{Content: []contentBlock{{Type: "text", Text: string(result)}}}}
}

func shareFile(args json.RawMessage, apiClient *client.Client, log func(string, ...any)) response {
	var p struct {
		Path          string `json:"path"`
		TTL           string `json:"ttl"`
		BurnAfterRead *bool  `json:"burn_after_read"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return toolError("invalid arguments: " + err.Error())
	}
	if p.Path == "" {
		return toolError("path is required")
	}
	if p.TTL == "" {
		p.TTL = "24h"
	}
	switch p.TTL {
	case "1h", "24h", "7d":
	default:
		return toolError("invalid ttl: must be 1h, 24h, or 7d")
	}
	burn := true
	if p.BurnAfterRead != nil {
		burn = *p.BurnAfterRead
	}

	// Read file directly — contents never enter the agent's context
	fileData, err := os.ReadFile(p.Path)
	if err != nil {
		return toolError("read file: " + err.Error())
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return toolError("generate key: " + err.Error())
	}

	ciphertext, err := crypto.Encrypt(fileData, key)
	if err != nil {
		return toolError("encrypt: " + err.Error())
	}

	ctx := context.Background()
	id, _, err := apiClient.CreateSecret(ctx, ciphertext, p.TTL, burn)
	if err != nil {
		return toolError("create secret: " + err.Error())
	}

	serverURL := os.Getenv("PASSWD_SERVER")
	if serverURL == "" {
		serverURL = "https://passwd.page"
	}

	secretURL := fmt.Sprintf("%s/s/%s#%s", serverURL, id, crypto.KeyToBase64url(key))
	log("shared file %s as secret: %s", p.Path, id)

	result, _ := json.Marshal(map[string]string{"url": secretURL})
	return response{Result: toolResult{Content: []contentBlock{{Type: "text", Text: string(result)}}}}
}

func retrieveSecret(args json.RawMessage, apiClient *client.Client, log func(string, ...any)) response {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return toolError("invalid arguments: " + err.Error())
	}
	if p.URL == "" {
		return toolError("url is required")
	}

	parsed, err := url.Parse(p.URL)
	if err != nil {
		return toolError("invalid url: " + err.Error())
	}

	// Extract secret ID from path: /s/{id}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] != "s" {
		return toolError("invalid passwd.page URL path, expected /s/{id}")
	}
	id := pathParts[1]

	fragment := parsed.Fragment
	if fragment == "" {
		return toolError("URL is missing #key fragment")
	}

	key, err := crypto.Base64urlToKey(fragment)
	if err != nil {
		return toolError("invalid key in fragment: " + err.Error())
	}

	ctx := context.Background()
	ciphertext, _, err := apiClient.GetSecret(ctx, id)
	if err != nil {
		return toolError("get secret: " + err.Error())
	}

	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return toolError("decrypt: " + err.Error())
	}

	log("retrieved secret: %s", id)

	result, _ := json.Marshal(map[string]string{"secret": string(plaintext)})
	return response{Result: toolResult{Content: []contentBlock{{Type: "text", Text: string(result)}}}}
}

func toolError(msg string) response {
	// Use json.Marshal to safely encode the error message, preventing JSON injection.
	errJSON, _ := json.Marshal(map[string]string{"error": msg})
	return response{Result: toolResult{Content: []contentBlock{{Type: "text", Text: string(errJSON)}}}}
}
