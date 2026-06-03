package webhook

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/argoproj-labs/argocd-image-updater/pkg/argocd"
)

// GARWebhook handles Google Artifact Registry (and legacy Container Registry)
// webhook events. GAR does not POST to an endpoint directly; it publishes
// change notifications to a Pub/Sub topic (named `gcr`). A Pub/Sub push
// subscription then POSTs those messages to this handler, wrapped in the
// standard push envelope.
//
// Reference (notification payload):
// https://cloud.google.com/artifact-registry/docs/configure-notifications
type GARWebhook struct {
	secret string
}

// NewGARWebhook creates a new GAR webhook handler
func NewGARWebhook(secret string) *GARWebhook {
	return &GARWebhook{
		secret: secret,
	}
}

// GetRegistryType returns the registry type this handler supports
func (g *GARWebhook) GetRegistryType() string {
	return "gar"
}

// garPushEnvelope is the Pub/Sub push delivery envelope. The actual GAR
// notification is base64-encoded in message.data.
// Reference: https://cloud.google.com/pubsub/docs/push#receive_push
type garPushEnvelope struct {
	Message struct {
		Attributes map[string]string `json:"attributes"`
		Data       string            `json:"data"`
		MessageID  string            `json:"messageId"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// garNotification is the GAR change notification payload. Both `tag` and
// `digest` are full image references, e.g.
//
//	tag:    europe-north1-docker.pkg.dev/my-project/my-repo/my-image:1.1
//	digest: europe-north1-docker.pkg.dev/my-project/my-repo/my-image@sha256:6ec1...
type garNotification struct {
	Action string `json:"action"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// Validate validates the GAR webhook payload
func (g *GARWebhook) Validate(r *http.Request) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("invalid HTTP method: %s", r.Method)
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return fmt.Errorf("invalid content type: %s", contentType)
	}

	// Pub/Sub push lets us append a query string to the subscription's
	// endpoint URL, so we authenticate the same way as the other handlers:
	// a shared secret in the `secret` query parameter (image-updater does
	// not verify the Pub/Sub OIDC token).
	if g.secret != "" {
		secret := r.URL.Query().Get("secret")
		if secret == "" {
			secret = r.Header.Get("X-Webhook-Secret")
		}
		if secret == "" {
			return fmt.Errorf("missing webhook secret")
		}
		if subtle.ConstantTimeCompare([]byte(secret), []byte(g.secret)) != 1 {
			return fmt.Errorf("invalid webhook secret")
		}
	}

	return nil
}

// Parse processes the GAR webhook payload and returns a WebhookEvent.
//
// Non-push (raw notification) bodies are also accepted for testing and for
// setups that deliver the notification without the Pub/Sub envelope.
//
// Returns (nil, nil) for notifications that should be acknowledged but must
// not trigger an update (e.g. DELETE actions); the server treats that as a
// 200 no-op so Pub/Sub does not redeliver.
func (g *GARWebhook) Parse(r *http.Request) (*argocd.WebhookEvent, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	notification, err := decodeGARNotification(body)
	if err != nil {
		return nil, err
	}

	// Only image uploads / new tags should trigger an update check. DELETE
	// (and any other action) is acknowledged as a no-op.
	if !strings.EqualFold(notification.Action, "INSERT") {
		return nil, nil
	}

	var registryURL, repository, tag, digest string

	// Prefer the `tag` reference: it carries the human tag we match on. Fall
	// back to `digest` for tagless uploads (the matcher keys on registry +
	// repository, so a tagless push still triggers a recheck of that image).
	if notification.Tag != "" {
		registryURL, repository, tag, _, err = parseGARImageRef(notification.Tag)
		if err != nil {
			return nil, err
		}
	}
	if notification.Digest != "" {
		reg, repo, _, dig, derr := parseGARImageRef(notification.Digest)
		if derr != nil {
			return nil, derr
		}
		if registryURL == "" {
			registryURL = reg
		}
		if repository == "" {
			repository = repo
		}
		digest = dig
	}

	if repository == "" {
		return nil, fmt.Errorf("GAR notification has neither tag nor digest")
	}

	return &argocd.WebhookEvent{
		RegistryURL: registryURL,
		Repository:  repository,
		Tag:         tag,
		Digest:      digest,
	}, nil
}

// decodeGARNotification extracts the GAR notification from a request body,
// transparently unwrapping the Pub/Sub push envelope when present.
func decodeGARNotification(body []byte) (*garNotification, error) {
	var envelope garPushEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Message.Data != "" {
		decoded, derr := base64.StdEncoding.DecodeString(envelope.Message.Data)
		if derr != nil {
			return nil, fmt.Errorf("failed to base64-decode Pub/Sub message data: %w", derr)
		}
		body = decoded
	}

	var notification garNotification
	if err := json.Unmarshal(body, &notification); err != nil {
		return nil, fmt.Errorf("failed to parse GAR notification payload: %w", err)
	}
	if notification.Action == "" {
		return nil, fmt.Errorf("GAR notification missing action field")
	}
	return &notification, nil
}

// parseGARImageRef splits a fully-qualified image reference into its registry
// host, repository path, and tag or digest. It mirrors how image-updater's
// own image.NewFromIdentifier splits an imageName, so the resulting
// RegistryURL/Repository match the values stored on ImageUpdater CRs.
//
//	europe-north1-docker.pkg.dev/proj/repo/img:1.1        -> host, "proj/repo/img", tag "1.1"
//	europe-north1-docker.pkg.dev/proj/repo/img@sha256:ab  -> host, "proj/repo/img", digest "sha256:ab"
func parseGARImageRef(ref string) (registryURL, repository, tag, digest string, err error) {
	slash := strings.Index(ref, "/")
	if slash < 0 {
		return "", "", "", "", fmt.Errorf("invalid image reference %q: no registry host", ref)
	}
	registryURL = ref[:slash]
	remainder := ref[slash+1:]

	if at := strings.Index(remainder, "@"); at >= 0 {
		repository = remainder[:at]
		digest = remainder[at+1:]
	} else if colon := strings.LastIndex(remainder, ":"); colon >= 0 {
		repository = remainder[:colon]
		tag = remainder[colon+1:]
	} else {
		repository = remainder
	}

	if repository == "" {
		return "", "", "", "", fmt.Errorf("invalid image reference %q: empty repository", ref)
	}
	return registryURL, repository, tag, digest, nil
}
