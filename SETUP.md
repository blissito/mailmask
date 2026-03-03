# MailMask — Setup Guide

## Prerequisites
- Node.js (tsx runtime)
- AWS account with SES and S3 access
- MercadoPago account (for billing)
- SQLite

## AWS S3 Buckets

The app requires two S3 buckets. They are **not** created automatically — you must create them before running the app:

```bash
aws s3 mb s3://mailmask-inbound --region us-east-1
aws s3 mb s3://mailmask-backups --region us-east-1
```

| Bucket | Env var | Default | Purpose |
|--------|---------|---------|---------|
| Inbound emails | `S3_BUCKET` | `mailmask-inbound` | SES stores incoming emails here |
| Backups | `S3_BACKUP_BUCKET` | `mailmask-backups` | Daily JSON backups (cron at 4:00 UTC) + manual backups from admin panel |

## Running

```bash
npm install
npm run dev   # Dev server on :8000
npm test      # Run tests
```
