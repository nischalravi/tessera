package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Azure is a Blob Storage container. Auth is a shared-access signature from
// AZURE_STORAGE_SAS_TOKEN when set, else a bearer token of the workload's
// managed identity.
type Azure struct {
	T *Target
	D Deps
}

const azureVersion = "2023-11-03"

// Location implements Store.
func (a *Azure) Location() string { return a.T.String() }

func (a *Azure) blobURL(key string) (string, error) {
	k, err := a.T.key(key)
	if err != nil {
		return "", err
	}
	base := a.T.Endpoint
	if base == "" {
		base = "https://" + a.T.Account + ".blob.core.windows.net"
	}
	return base + "/" + a.T.Bucket + "/" + k, nil
}

func (a *Azure) sas() string {
	if a.D.Azure != nil && a.D.Azure.Getenv != nil {
		return strings.TrimPrefix(strings.TrimSpace(a.D.Azure.Getenv("AZURE_STORAGE_SAS_TOKEN")), "?")
	}
	return strings.TrimPrefix(strings.TrimSpace(os.Getenv("AZURE_STORAGE_SAS_TOKEN")), "?")
}

func (a *Azure) do(ctx context.Context, method, key string, body []byte, hdr map[string]string) (*http.Response, error) {
	raw, err := a.blobURL(key)
	if err != nil {
		return nil, err
	}
	if sas := a.sas(); sas != "" {
		raw += "?" + sas
	}
	return a.send(ctx, method, raw, body, hdr)
}

// containerURL is the Get Container Properties URL (restype=container), with the SAS token when one is set.
func (a *Azure) containerURL() string {
	base := a.T.Endpoint
	if base == "" {
		base = "https://" + a.T.Account + ".blob.core.windows.net"
	}
	raw := base + "/" + a.T.Bucket + "?restype=container"
	if sas := a.sas(); sas != "" {
		raw += "&" + sas
	}
	return raw
}

func (a *Azure) send(ctx context.Context, method, raw string, body []byte, hdr map[string]string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-ms-version", azureVersion)
	if a.sas() == "" {
		tok, err := a.D.Azure.Token(ctx, "https://storage.azure.com")
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return a.D.HTTP.Do(req)
}

// Put implements Store.
func (a *Azure) Put(ctx context.Context, key string, data []byte, o PutOptions) (string, error) {
	hdr := map[string]string{"x-ms-blob-type": "BlockBlob", "Content-Type": orDefault(o.ContentType), "If-None-Match": "*"}
	if !o.RetainUntil.IsZero() && a.T.Immutable == "version" {
		// version-level immutability: the container must have it enabled
		hdr["x-ms-immutability-policy-until-date"] = o.RetainUntil.UTC().Format(time.RFC1123)
		hdr["x-ms-immutability-policy-mode"] = "Locked"
	}
	for _, k := range sortedKeys(o.Metadata) {
		hdr["x-ms-meta-"+strings.ReplaceAll(strings.ToLower(k), "-", "_")] = o.Metadata[k]
	}
	resp, err := a.do(ctx, http.MethodPut, key, data, hdr)
	if err != nil {
		return "", fmt.Errorf("objstore: azure put: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict:
		return "", ErrExists // BlobAlreadyExists is 409 on some paths, 412 with If-None-Match
	case resp.StatusCode/100 != 2:
		return "", fmt.Errorf("objstore: azure put: %s", resp.Status)
	}
	return resp.Header.Get("x-ms-version-id"), nil
}

// Get implements Store.
func (a *Azure) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := a.do(ctx, http.MethodGet, key, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("objstore: azure get: %w", unwrapURL(err))
	}
	return readBody(resp, "azure get")
}

// VerifyRetention implements Verifier. With worm=container no per-blob policy is sent, so the container itself
// must carry a time-based retention (immutability) policy: Get Container Properties has to report
// x-ms-has-immutability-policy: true, otherwise anchors are deletable by anyone holding the blob role.
// The data plane does not say whether the policy is locked, so locking it stays the operator's job (a policy
// that is only "unlocked" can still be shortened or deleted). With worm=version every Put carries a locked
// per-blob policy and fails on a container without version-level immutability, so there is nothing to check.
func (a *Azure) VerifyRetention(ctx context.Context) error {
	if a.T.Immutable != "container" {
		return nil
	}
	resp, err := a.send(ctx, http.MethodGet, a.containerURL(), nil, nil)
	if err != nil {
		return fmt.Errorf("objstore: azure container: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("objstore: azure container properties: %s (the anchor identity needs read access to the container's properties to verify its immutability policy)", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("x-ms-has-immutability-policy"), "true") {
		return errors.New("objstore: the Azure container has no immutability policy (add a time-based retention policy and lock it: az storage container immutability-policy create, then lock)")
	}
	return nil
}
