# FunLearn — Cloudflare Pages + D1

This project upgrades the supplied FunLearn single-page application without removing its existing local-first features. The original local database, local video workflow, Online Learning tree, notes, XP, coins, streaks, achievements, Reward Shop, custom rewards, backup/restore, and responsive dark UI remain in `index.html`.

The upgrade adds an additive account layer:

- **Cloudflare Pages Functions** expose `/api/register`, `/api/login`, `/api/logout`, `/api/me`, `/api/sync`, and `/api/progress`.
- **Cloudflare D1** stores users, hashed passwords, secure session-token hashes, per-user application state, and relational Online Learning video progress.
- Passwords are hashed server-side with PBKDF2-HMAC-SHA-256 and a per-user random salt. Plaintext passwords never enter D1 or browser storage.
- Sessions use an `HttpOnly; Secure; SameSite=Lax` cookie. API operations resolve the user from the session and never trust a frontend-supplied `user_id`.
- The existing local state remains a cache/offline fallback. Authenticated changes are debounced before upload, and the browser attempts a sync again when it returns online.
- YouTube playback uses the official IFrame Player API when available. Progress is sampled every five seconds, resumes from the last saved position, and completes at `ended` or at least 95%. Direct `.mp4`, `.webm`, `.mov`, and similar URLs continue to use HTML5 video; unsupported providers are still opened without pretending progress is available.

## Project layout

```text
.
├── index.html
├── functions/api/[[path]].js
├── migrations/0001_initial.sql
├── wrangler.toml
└── README.md
```

## Create the D1 database

Install Wrangler and authenticate with the Cloudflare account that owns the Pages project:

```bash
npm install -g wrangler
wrangler login
wrangler d1 create funlearn-db
```

Copy the returned database ID into `wrangler.toml` in place of `REPLACE_WITH_D1_DATABASE_ID`.

Apply the schema locally or to the remote database:

```bash
wrangler d1 migrations apply funlearn-db --local
wrangler d1 migrations apply funlearn-db --remote
```

The schema is relational for ownership-sensitive records. Larger flexible application state is kept as versioned JSON in `user_data`, while `video_progress` is structured so it can be queried, indexed, and migrated independently.

## Local development

From this directory:

```bash
wrangler pages dev . --d1 DB=funlearn-db
```

Open the local URL printed by Wrangler. Test registration with a username of 3–32 letters, numbers, `_`, `.`, or `-`, and a password of at least 10 characters.

## Cloudflare Pages deployment

1. Create a Pages project connected to this directory or repository.
2. Set the build output directory to `.`. There is no frontend build step.
3. Bind the D1 database to the Pages project with binding name **`DB`**.
4. Deploy with the Pages dashboard or:

```bash
wrangler pages deploy . --project-name funlearn
```

The `functions/api/[[path]].js` file is deployed automatically as Pages Functions. No database credential or password secret is placed in the frontend.

## Account and sync behavior

When the user is logged in, the account control appears in the top-right corner. The server state is loaded after `/api/me` succeeds. Existing local data is not deleted. During first registration, the app asks whether the local state should be uploaded or the account state should be used instead. While offline, the original local persistence continues to work; when connectivity returns, the adapter attempts a debounced sync.

The current merge policy is intentionally conservative: ordinary state sync sends the current local snapshot, while video progress is upserted per `(user_id, module_id)` and completion is monotonic, so an already completed module cannot be reverted by a stale browser. The `last_watched_at` timestamp is retained for future field-level conflict resolution.

## Testing checklist

- Register two different users and confirm both can log in.
- Confirm the same invalid login response is returned for an unknown username and a wrong password.
- Inspect D1 and verify `password_hash` is PBKDF2-formatted, not plaintext.
- Log in as User A, add a course/chapter/module, notes, XP, and a reward redemption; log out.
- Log in as User B and confirm User A’s data is absent.
- Log back in as User A and confirm the Online Learning tree, notes, XP, coins, achievements, and rewards return.
- Open a YouTube module, play it, reload, and confirm the player attempts to resume from the saved position. Confirm progress is sampled at five-second intervals rather than every frame.
- Complete an online module at `ended` or 95% and verify the existing achievement/XP/coin pipeline is used once.
- Open a direct video URL and verify HTML5 progress is persisted.
- Disable the network, edit local data, re-enable it, and confirm the sync status moves through offline/saving/synced states.
- Use the existing backup/restore and delete-data controls; they remain local-data controls and are not silently destructive to the remote account.
- Test desktop and narrow mobile viewport layouts.

## Important production hardening

For a public production launch, add rate limiting at the Cloudflare edge or a Durable Object, add CSRF protection if the API later accepts cross-site unsafe requests, and consider a password-reset/recovery flow before relying on username-only accounts for important user data. The current version deliberately has no email recovery because the requested first version does not collect email.
