package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultServerURL = "https://passwd.page"
	userAgent        = "passwd-cli/1.0"
	defaultTimeout   = 10 * time.Second
)

// Sentinel errors returned by Client methods.
var (
	ErrNotFound    = errors.New("secret not found")
	ErrRateLimited = errors.New("rate limited")
	ErrServerError = errors.New("server error")
)

// Client is an HTTP client for the passwd.page API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates an API client. If serverURL is empty, it checks the
// PASSWD_SERVER environment variable, then falls back to https://passwd.page.
func NewClient(serverURL string) *Client {
	if serverURL == "" {
		serverURL = os.Getenv("PASSWD_SERVER")
	}
	if serverURL == "" {
		serverURL = defaultServerURL
	}
	// Enforce HTTPS for non-localhost servers to prevent credential interception.
	if u, err := url.Parse(serverURL); err == nil {
		host := strings.Split(u.Hostname(), ":")[0]
		isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if u.Scheme == "http" && !isLocal {
			fmt.Fprintf(os.Stderr, "warning: PASSWD_SERVER uses http:// for non-localhost host %q; secrets may be intercepted\n", u.Host)
		}
	}
	return &Client{
		baseURL: serverURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// createRequest is the JSON body for POST /api/secrets.
type createRequest struct {
	Ciphertext    string `json:"ciphertext"`
	ExpiresIn     string `json:"expiresIn"`
	BurnAfterRead bool   `json:"burnAfterRead"`
}

// createResponse is the JSON response for a successful secret creation.
type createResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

// getResponse is the JSON response for a successful secret retrieval.
type getResponse struct {
	Ciphertext    string `json:"ciphertext"`
	BurnAfterRead bool   `json:"burnAfterRead"`
}

// errorResponse matches the server's structured error format.
type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// CreateSecret posts an encrypted secret to the server.
// Returns the secret ID and expiry time.
func (c *Client) CreateSecret(ctx context.Context, ciphertext string, expiresIn string, burnAfterRead bool) (id string, expiresAt string, err error) {
	body, err := json.Marshal(createRequest{
		Ciphertext:    ciphertext,
		ExpiresIn:     expiresIn,
		BurnAfterRead: burnAfterRead,
	})
	if err != nil {
		return "", "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/secrets", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return "", "", err
	}

	var result createResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("decode response: %w", err)
	}
	return result.ID, result.ExpiresAt, nil
}

// GetSecret retrieves an encrypted secret by ID.
// Returns the ciphertext and burn-after-read flag.
func (c *Client) GetSecret(ctx context.Context, id string) (ciphertext string, burnAfterRead bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/secrets/"+id, nil)
	if err != nil {
		return "", false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return "", false, err
	}

	var result getResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", false, fmt.Errorf("decode response: %w", err)
	}
	return result.Ciphertext, result.BurnAfterRead, nil
}

// checkStatus maps non-2xx HTTP responses to sentinel errors.
func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		var errResp errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error.Message != "" {
			return fmt.Errorf("%w: %s", ErrServerError, errResp.Error.Message)
		}
		return fmt.Errorf("%w: HTTP %d", ErrServerError, resp.StatusCode)
	}
}
