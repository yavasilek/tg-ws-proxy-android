# CI and pre-publication checks

Updated 2026-11-12.

- Automatic checks run for relevant changes on `main` and ready pull requests targeting `main`.
- Feature-branch pushes do not duplicate their PR checks. Draft PRs wait until `ready_for_review`.
- New commits cancel superseded branch/PR verification. Version-tag checks are not cancelled.
- Documentation and Work Graph metadata alone do not start automatic check runs.
- Full test commands, matrices and job dependencies are preserved.

Version tags (`v*`) and manual dispatch run every existing check job without path filtering. Before a manual production deployment, run the full workflow (`android.yml`) with **Run workflow** on the exact source revision and wait for every required job to succeed. A queued, skipped, cancelled or billing-blocked full check is not a successful release check. Existing local/server preflight commands remain required.


Where a workflow publishes artifacts, publication remains after its checks. Changes to CI scheduling do not authorize a production deployment, SMS send, signature change or billing change.
