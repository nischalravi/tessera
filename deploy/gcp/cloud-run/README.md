# Google Cloud Run (reference)

```bash
gcloud run services replace service.yaml --region REGION
```

- Two containers in one service (`ui` nginx is the ingress container, `api` is the sidecar on localhost:8000).
  Keep `minScale >= 2` and CPU always allocated: Tessera runs background loops that must not be throttled.
- Cloud Run has no read-only-root-filesystem switch; the images are non-root and writable paths are the
  in-memory volumes in the YAML.
- Put the service behind an external HTTPS load balancer with a Google-managed certificate and a serverless NEG
  (`deploy/terraform/gcp`); `ingress: internal-and-cloud-load-balancing` blocks direct run.app access.
- Secrets are Secret Manager versions (`secretKeyRef`); grant the service account `secretmanager.secretAccessor`
  on those secrets only. The prod audit anchor still needs an S3 bucket and AWS keys (docs/deploy/README.md,
  "Audit anchor").
- Probes on `/livez` and `/readyz`, and leader election: available once #517 merges.
- Migrations: first revision start applies them (advisory lock). For a gated rollout create a Cloud Run job with
  the api image, args `check-db` and only `TESSERA_DB`.
