# Demo page

Static page for `wakimworks.com/judewakim/soc2-evidence-kit/`. No backend, no API, no cost beyond hosting.

- **Sample report:** `sample-report.js` and `sample/` are produced by running the real scanner against a
  simulated AWS account (moto) set up as a fictional company. Regenerate with:

  ```bash
  pip install -e ".[dev]"
  python web/tools/build_sample.py
  ```

- **Visitor's own report:** the visitor runs `soc2kit` in AWS CloudShell and opens `report.json` on the page.
  The file is read with `FileReader`; the page's CSP sets `connect-src 'none'`, so it cannot send the file
  anywhere. Report fields are validated, length-capped and written with `textContent` only.

## Publish

Upload everything in `web/` except `tools/` and this README, staging path first:

```bash
aws s3 sync web/ s3://<site-bucket>/judewakim/soc2-evidence-kit/ \
  --exclude "tools/*" --exclude "README.md" --delete
aws cloudfront create-invalidation --distribution-id <id> --paths "/judewakim/soc2-evidence-kit/*"
```

In CloudFront, add the response headers `X-Frame-Options: DENY` and
`Content-Security-Policy: frame-ancestors 'none'` (they can't be set from a meta tag), same as S3 Sentry.

`preview.png` (2400×1060) is the image for the portfolio card.
