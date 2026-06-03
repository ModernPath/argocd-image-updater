package webhook

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewGARWebhook(t *testing.T) {
	secret := "test-secret"
	webhook := NewGARWebhook(secret)

	if webhook == nil {
		t.Fatal("expected webhook to be non-nil")
	} else if webhook.secret != secret {
		t.Errorf("expected secret to be %q, got %q", secret, webhook.secret)
	}
}

func TestGARWebhook_GetRegistryType(t *testing.T) {
	webhook := NewGARWebhook("")
	if got := webhook.GetRegistryType(); got != "gar" {
		t.Errorf("expected registry type to be %q, got %q", "gar", got)
	}
}

func TestGARWebhook_Validate(t *testing.T) {
	secret := "test-secret"
	webhook := NewGARWebhook(secret)

	tests := []struct {
		name        string
		method      string
		contentType string
		query       string
		header      map[string]string
		expectError bool
	}{
		{
			name:        "valid POST with correct secret in query",
			method:      "POST",
			contentType: "application/json",
			query:       "?secret=test-secret",
			expectError: false,
		},
		{
			name:        "valid POST with correct secret in header",
			method:      "POST",
			contentType: "application/json",
			header:      map[string]string{"X-Webhook-Secret": "test-secret"},
			expectError: false,
		},
		{
			name:        "invalid HTTP method",
			method:      "GET",
			contentType: "application/json",
			query:       "?secret=test-secret",
			expectError: true,
		},
		{
			name:        "invalid content type",
			method:      "POST",
			contentType: "text/plain",
			query:       "?secret=test-secret",
			expectError: true,
		},
		{
			name:        "missing secret",
			method:      "POST",
			contentType: "application/json",
			expectError: true,
		},
		{
			name:        "wrong secret",
			method:      "POST",
			contentType: "application/json",
			query:       "?secret=nope",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/webhook"+tt.query, nil)
			req.Header.Set("Content-Type", tt.contentType)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			err := webhook.Validate(req)
			if tt.expectError && err == nil {
				t.Errorf("expected error, got nil")
			} else if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// pubsubPush wraps a GAR notification in a Pub/Sub push envelope.
func pubsubPush(t *testing.T, notification string) string {
	t.Helper()
	envelope := map[string]any{
		"message": map[string]any{
			"attributes": map[string]string{"action": "INSERT"},
			"data":       base64.StdEncoding.EncodeToString([]byte(notification)),
			"messageId":  "123",
		},
		"subscription": "projects/p/subscriptions/s",
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}
	return string(b)
}

func TestGARWebhook_Parse(t *testing.T) {
	const host = "europe-north1-docker.pkg.dev"
	const repo = "plat-test-gke-b342/modernpath-ex/app"

	tests := []struct {
		name       string
		body       string
		wantNil    bool
		wantErr    bool
		wantRepo   string
		wantTag    string
		wantDigest string
		wantRegURL string
	}{
		{
			name:       "pub/sub push, tag + digest INSERT",
			body:       pubsubPush(t, `{"action":"INSERT","digest":"`+host+`/`+repo+`@sha256:abc","tag":"`+host+`/`+repo+`:main-deadbeef"}`),
			wantRepo:   repo,
			wantTag:    "main-deadbeef",
			wantDigest: "sha256:abc",
			wantRegURL: host,
		},
		{
			name:       "raw notification (no envelope), tag only",
			body:       `{"action":"INSERT","tag":"` + host + `/` + repo + `:main-deadbeef"}`,
			wantRepo:   repo,
			wantTag:    "main-deadbeef",
			wantRegURL: host,
		},
		{
			name:       "digest-only INSERT still matches repo",
			body:       `{"action":"INSERT","digest":"` + host + `/` + repo + `@sha256:abc"}`,
			wantRepo:   repo,
			wantDigest: "sha256:abc",
			wantRegURL: host,
		},
		{
			name:    "DELETE is a no-op",
			body:    `{"action":"DELETE","tag":"` + host + `/` + repo + `:main-deadbeef"}`,
			wantNil: true,
		},
		{
			name:    "missing action is an error",
			body:    `{"tag":"` + host + `/` + repo + `:main-deadbeef"}`,
			wantErr: true,
		},
		{
			name:    "malformed json is an error",
			body:    `{not json`,
			wantErr: true,
		},
	}

	webhook := NewGARWebhook("")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			event, err := webhook.Parse(req)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if event != nil {
					t.Fatalf("expected nil event, got %+v", event)
				}
				return
			}
			if event == nil {
				t.Fatalf("expected event, got nil")
			}
			if event.RegistryURL != tt.wantRegURL {
				t.Errorf("RegistryURL: want %q, got %q", tt.wantRegURL, event.RegistryURL)
			}
			if event.Repository != tt.wantRepo {
				t.Errorf("Repository: want %q, got %q", tt.wantRepo, event.Repository)
			}
			if event.Tag != tt.wantTag {
				t.Errorf("Tag: want %q, got %q", tt.wantTag, event.Tag)
			}
			if event.Digest != tt.wantDigest {
				t.Errorf("Digest: want %q, got %q", tt.wantDigest, event.Digest)
			}
		})
	}
}

func TestParseGARImageRef(t *testing.T) {
	const host = "europe-north1-docker.pkg.dev"

	t.Run("tag ref", func(t *testing.T) {
		reg, repo, tag, digest, err := parseGARImageRef(host + "/proj/repo/img:1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reg != host || repo != "proj/repo/img" || tag != "1.1" || digest != "" {
			t.Errorf("got reg=%q repo=%q tag=%q digest=%q", reg, repo, tag, digest)
		}
	})

	t.Run("digest ref", func(t *testing.T) {
		reg, repo, tag, digest, err := parseGARImageRef(host + "/proj/repo/img@sha256:ab")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reg != host || repo != "proj/repo/img" || tag != "" || digest != "sha256:ab" {
			t.Errorf("got reg=%q repo=%q tag=%q digest=%q", reg, repo, tag, digest)
		}
	})

	t.Run("no registry host", func(t *testing.T) {
		if _, _, _, _, err := parseGARImageRef("img:1.1"); err == nil {
			t.Errorf("expected error for ref without registry host")
		}
	})
}
