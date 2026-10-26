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

Run in AWS CloudShell from the repo root. The site is the `wakimworks.com` bucket behind CloudFront
(caching is disabled, so no invalidation is needed). Stage first, check it, then promote:

```bash
BUCKET=wakimworks.com
aws s3 sync web/ "s3://$BUCKET/judewakim/_staging/soc2-evidence-kit/" --exclude "tools/*" --exclude "README.md" --delete
# test https://wakimworks.com/judewakim/_staging/soc2-evidence-kit/
aws s3 sync web/ "s3://$BUCKET/judewakim/soc2-evidence-kit/" --exclude "tools/*" --exclude "README.md" --delete
aws s3 rm "s3://$BUCKET/judewakim/_staging/soc2-evidence-kit/" --recursive
```

Security headers (frame blocking, HSTS, nosniff) come from the distribution's managed SecurityHeadersPolicy.

`preview.png` (2400×1640) is the image for the portfolio card.
