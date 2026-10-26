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

The live copy is served from the [wakimworks.com](https://github.com/Judewakim/wakimworks.com) repo at
`judewakim/soc2-evidence-kit/`. That repo deploys on push to `main` with `aws s3 sync --delete`, so
uploading to the bucket by hand gets overwritten on the next deploy. To publish a change:

1. Regenerate the sample if the scanner changed: `python web/tools/build_sample.py`
2. Copy everything in `web/` except `tools/` and this README into `judewakim/soc2-evidence-kit/` in the
   wakimworks.com repo, on a branch.
3. Review the branch, then merge it to deploy. No CloudFront invalidation is needed; caching is disabled.

Security headers (frame blocking, HSTS, nosniff) come from the distribution's managed SecurityHeadersPolicy.

`preview.png` (2400×1640) is the image for the portfolio card.
