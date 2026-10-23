package objstore

import (
	"bytes"
	"context"
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
