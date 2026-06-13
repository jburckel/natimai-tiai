// Package api is the HTTP client to the Tiai server.
//
// Under Windows, Go's HTTP client uses the system certificate store, so a
// certificate issued by the internal CA validates without extra config.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"tiai/agent/internal/models"
)

// Client talks to the Tiai API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New builds a client with the given timeout.
func New(baseURL, token string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: timeout},
	}
}

// SetToken updates the bearer token (after enrollment).
func (c *Client) SetToken(token string) { c.token = token }

// Enroll registers the machine and returns its per-machine token.
func (c *Client) Enroll(ctx context.Context, secret string, req models.EnrollRequest) (*models.EnrollResponse, error) {
	var out models.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/enroll", map[string]string{
		"X-Enrollment-Secret": secret,
	}, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat reports state and returns pending commands.
func (c *Client) Heartbeat(ctx context.Context, req models.HeartbeatRequest) (*models.HeartbeatResponse, error) {
	var out models.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/heartbeat", c.authHeader(), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostResult reports a command's execution outcome.
func (c *Client) PostResult(ctx context.Context, commandID string, res models.CommandResult) error {
	path := fmt.Sprintf("/api/v1/agent/commands/%s/result", commandID)
	return c.do(ctx, http.MethodPost, path, c.authHeader(), res, nil)
}

func (c *Client) authHeader() map[string]string {
	return map[string]string{"Authorization": "Bearer " + c.token}
}

func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
