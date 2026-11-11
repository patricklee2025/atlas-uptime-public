# Atlas uptime monitor

Five-minute cloud checks for four public websites, with private email and optional Pushover alerts. This is a fresh source-only deployment. Do not import another repository's Git history, runtime branch, reports, or Actions logs.

## Sites

| Monitor | Public URL | Check |
|---|---|---|
| Atlas Production | https://myatlasapp.com/ | HTTPS success and nonempty body |
| AMS Customer Payments | https://www.amsonlinesms.com/AMSCustomer/ | HTTPS success and Account Number text |
| NCM ePay | https://www.amsonlinesms.com/NCMepay/ | HTTPS success and nonempty body |
| Atlas Marketing Studio | https://atlasmarketingstudio.app/ | HTTPS success and ATLAS Marketing Studio text |

These are read-only page checks, not login, database, or payment transaction tests. Failed requests get three attempts with ten seconds between attempts. Monitoring continues throughout an outage. Alerts are sent once on DOWN and once on RECOVERED; recurring reminders are disabled. A failed delivery remains queued for retry independently of successful channels. Delivery retries can duplicate a message if a provider accepted it before a connection failed.

## Privacy boundary

- Source code, the four public URLs, workflow names, execution times/durations, generic job success/failure, and encrypted snapshot sizes are public. Timing and size can reveal patterns; this is not traffic-analysis protection.
- Site results, response times, event messages, and reports are encrypted using authenticated Fernet encryption before saving to the `encrypted-state` branch. The only committed runtime file is `state.enc`.
- Public monitor logs suppress child-process output and per-site job summaries. An observed site outage does not itself fail the public job. A monitor, storage, or delivery error does fail it with a generic diagnostic.
- Plaintext exists temporarily on the GitHub-hosted runner and is deleted after each operation. No plaintext reports are uploaded as Actions artifacts, caches, Pages content, or Git files.
- Credentials and the encryption key belong in repository Actions Secrets. Anyone who can modify trusted workflow code or read these secrets must be trusted. Encryption does not protect against a compromised maintainer or runner.
- The encryption key is separate from alert credentials. Back it up securely. Losing it prevents reading saved state; rotating it requires decrypting and re-encrypting the current snapshot. Never replace the key casually to fix a failed job. Anyone obtaining the key may decrypt previously published ciphertext.
- Runtime commits use a GitHub noreply bot address. Publish the initial source using a noreply author too. Create a fresh repository; never fork, mirror, or change visibility on an old operational repository.
- One day of samples is retained in the current encrypted snapshot. Pending notifications are retained until delivered. The snapshot branch is replaced with a single root commit using a force-with-lease check; historical ciphertext may remain recoverable on GitHub. This is not secure deletion.

## Activate

Keep the independent UptimeRobot monitors active until several GitHub checks and actual alert deliveries have been verified. GitHub runs on its own servers; a local PC hosts file does not affect it.

1. Publish these files to a new public repository, with `main` as the default branch. Do not include `.venv`, local reports, keys, archives, or any previous `.git` directory. Standard GitHub-hosted runners in public repositories are free; larger runners and other billable products are not used. An account-level restriction can still prevent jobs from starting.
2. Add **repository Secrets** in Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `STATE_ENCRYPTION_KEY` | A newly generated Fernet key; keep a secure backup |
| `SMTP_USERNAME` | Google sender account |
| `SMTP_PASSWORD` | Approved Google app password, not the normal account password |
| `EMAIL_FROM` | Authorized sender address |
| `EMAIL_TO` | One address or comma-separated recipients |
| `PUSHOVER_APP_TOKEN` | Optional: existing Pushover application token |
| `PUSHOVER_USER_KEY` | Optional: existing Pushover user key |

Generate the encryption key on your own trusted computer with Python, and paste the output directly into GitHub Secrets. Do not paste it into chat, a commit, an issue, or an Actions log:

```sh
python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

The workflow uses `smtp.gmail.com:587` with TLS. For Google Workspace, app passwords must be permitted by the administrator. GitHub cannot reveal values from another repository's Secrets; enter the values again from your password manager/provider. Existing Pushover credentials can be used, subject to that provider's plan. The free UptimeRobot mobile app is a separate notification system.

3. In **Variables**, leave `ALERT_CHANNELS` unset for email only, or set it to `email,pushover` after both channels are configured. Scheduled checks remain off until `UPTIME_ENABLED` is `true`.
4. Run **Test monitor safety** and confirm it passes. It uses mocks and does not contact the websites or send alerts.
5. Run **Private uptime checks** manually on `main`, choosing `initialize` once. This validates configuration and creates a new empty encrypted state. It refuses to overwrite existing state.
6. Run the same workflow with `test`. Confirm the labeled test reaches every selected destination. This does not change incident state.
7. Run it with `check`. Then set `UPTIME_ENABLED=true` and verify several scheduled runs. Five minutes is the target; GitHub can delay or skip schedules and can disable inactive public-repository schedules. Keep an independent monitoring provider as backup.
8. Pause the old scheduler only after the replacement is verified, to avoid duplicate alerts. Keep its repository and history private.

## Read private reports locally

Download only `state.enc` from the `encrypted-state` branch. Install the pinned requirements in a local virtual environment. Supply `STATE_ENCRYPTION_KEY` securely through your environment, then:

```sh
python public_runner.py decrypt --state /path/to/state.enc --output private-reports
```

The output directory must not already exist. Read `STATUS.md` or `status.html` locally; never upload them to a public repository. Do not run `monitor.py` directly in public CI: it produces plaintext reports and site logs. The provided workflow uses `public_runner.py` instead.

## Validation

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Tests cover probing, transitions, channel retry behavior, encrypted state authentication, wrong-key/tampering rejection, suppressed public output, and real Git snapshot writes/lease rejection using a disposable local repository. They do not prove live delivery or GitHub scheduling.

Official references: [GitHub billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), [Fernet](https://cryptography.io/en/latest/fernet/).
