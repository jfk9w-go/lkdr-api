package lkdr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfk9w-go/based"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type tokenStorage struct {
	tokens  *Tokens
	loadErr error
	updates []*Tokens
}

func (s *tokenStorage) LoadTokens(context.Context, string) (*Tokens, error) {
	return s.tokens, s.loadErr
}

func (s *tokenStorage) UpdateTokens(_ context.Context, _ string, tokens *Tokens) error {
	s.tokens = tokens
	s.updates = append(s.updates, tokens)
	return nil
}

type testExchange[R any] struct {
	Value         string `json:"value"`
	path          string
	authenticated bool
}

func (in testExchange[R]) Auth() bool         { return in.authenticated }
func (in testExchange[R]) Path() string       { return in.path }
func (in testExchange[R]) Response() (zero R) { return }

type testResponse struct {
	Result string `json:"result"`
}

func newTestClient(t *testing.T, now time.Time, storage TokenStorage, transport http.RoundTripper) *Client {
	t.Helper()

	client, err := NewClient(ClientParams{
		Phone:        "79999999999",
		Clock:        based.ClockFunc(func() time.Time { return now }),
		DeviceID:     "device-id",
		UserAgent:    "test-agent",
		TokenStorage: storage,
		Transport:    transport,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	return client
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestClientDo(t *testing.T) {
	storage := &tokenStorage{}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Errorf("Method = %q, want %q", req.Method, http.MethodPost)
		}
		if req.URL.String() != baseURL+"/test" {
			t.Errorf("URL = %q, want %q", req.URL.String(), baseURL+"/test")
		}
		if got := req.Header.Get("Content-Type"); got != "application/json;charset=UTF-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}

		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if got := body["value"]; got != "input" {
			t.Errorf("body value = %v, want input", got)
		}

		return response(http.StatusOK, `{"result":"output"}`), nil
	})
	client := newTestClient(t, time.Now(), storage, transport)

	out, err := client.Do(context.Background(), testExchange[testResponse]{Value: "input", path: "/test"})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if out.Result != "output" {
		t.Errorf("Do() result = %q, want output", out.Result)
	}
}

func TestClientDoErrors(t *testing.T) {
	transportErr := errors.New("transport failed")
	tests := []struct {
		name      string
		response  *http.Response
		transport error
		wantError string
		wantCode  ErrorCode
	}{
		{
			name:      "transport",
			transport: transportErr,
			wantError: "transport failed",
		},
		{
			name:      "API error",
			response:  response(http.StatusBadRequest, `{"code":"blocked.captcha","message":"blocked"}`),
			wantError: "blocked.captcha (blocked)",
			wantCode:  BlockedCaptcha,
		},
		{
			name:      "non-JSON error",
			response:  response(http.StatusBadGateway, "bad gateway"),
			wantError: http.StatusText(http.StatusBadGateway),
		},
		{
			name:      "invalid response",
			response:  response(http.StatusOK, "not-json"),
			wantError: "decode response body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, time.Now(), &tokenStorage{}, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return tt.response, tt.transport
			}))

			_, err := client.Do(context.Background(), testExchange[testResponse]{path: "/test"})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Do() error = %v, want containing %q", err, tt.wantError)
			}
			if tt.wantCode != "" {
				var clientErr Error
				if !errors.As(err, &clientErr) || clientErr.Code != tt.wantCode {
					t.Errorf("Do() error = %v, want Error code %q", err, tt.wantCode)
				}
			}
		})
	}
}

func TestClientDoUsesStoredToken(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	storage := &tokenStorage{tokens: &Tokens{
		Token:                 "access-token",
		TokenExpireIn:         DateTimeTZ(now.Add(time.Hour)),
		RefreshToken:          "refresh-token",
		RefreshTokenExpiresIn: dateTimeTZPtr(now.Add(24 * time.Hour)),
	}}
	client := newTestClient(t, now, storage, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Errorf("Authorization = %q", got)
		}
		return response(http.StatusOK, `{"result":"ok"}`), nil
	}))

	if _, err := client.Do(context.Background(), testExchange[testResponse]{path: "/test", authenticated: true}); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if len(storage.updates) != 0 {
		t.Errorf("token updates = %d, want 0", len(storage.updates))
	}
}

func TestClientDoRefreshesExpiredToken(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	storage := &tokenStorage{tokens: &Tokens{
		Token:                 "expired-token",
		TokenExpireIn:         DateTimeTZ(now),
		RefreshToken:          "refresh-token",
		RefreshTokenExpiresIn: dateTimeTZPtr(now.Add(24 * time.Hour)),
	}}
	var paths []string
	client := newTestClient(t, now, storage, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		switch req.URL.Path {
		case "/api/v1/auth/token":
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("refresh Authorization = %q, want empty", got)
			}
			return response(http.StatusOK, `{"token":"new-token","tokenExpireIn":"2026-08-25T13:00:00.000Z","refreshToken":"new-refresh","refreshTokenExpiresIn":"2026-08-26T12:00:00.000Z"}`), nil
		case "/api/test":
			if got := req.Header.Get("Authorization"); got != "Bearer new-token" {
				t.Errorf("Authorization = %q, want new token", got)
			}
			return response(http.StatusOK, `{"result":"ok"}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	}))

	if _, err := client.Do(context.Background(), testExchange[testResponse]{path: "/test", authenticated: true}); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if strings.Join(paths, ",") != "/api/v1/auth/token,/api/test" {
		t.Errorf("request paths = %v", paths)
	}
	if len(storage.updates) != 1 || storage.updates[0].Token != "new-token" {
		t.Errorf("token updates = %#v", storage.updates)
	}
}

func dateTimeTZPtr(value time.Time) *DateTimeTZ {
	dt := DateTimeTZ(value)
	return &dt
}
