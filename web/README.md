# laplat web

The web client — a **SvelteKit** app with an httpOnly-cookie **BFF**
(backend-for-frontend). First vertical slice: sign in, climb the assurance
ladder, browse the catalog, and join a live session.

## Why SvelteKit + a BFF (data minimization)

The browser stores **no account credentials**. The SvelteKit server holds the
`authd` access/refresh tokens in **httpOnly cookies** the page's JavaScript
cannot read, and every `authd` call happens server-side (in `load` functions and
form `actions`). The browser only ever receives rendered data — and, at join
time, the short-lived **LiveKit room token** it genuinely needs to reach the SFU
(a per-room grant, not your account credential).

Contrast a pure SPA, which must keep tokens in JS-readable `localStorage`. Moving
them server-side minimizes client-stored data and shrinks the token-theft
surface — matching the platform's PDPL / Decree 147 posture.

- Token cookies + helpers: `src/lib/server/session.ts`
- Server-side `authd` client (attaches the token, refreshes on 401): `src/lib/server/authd.ts`
- Per-request user resolution: `src/hooks.server.ts` → `locals.me`

## The slice (against the real authd API)

- **Sign in** — email OTP (`/v1/auth/email/{request,verify}`), a two-step server
  action that sets the cookies. In dev the console code sender logs the code to
  authd's output, so no SMTP vendor is needed.
- **My identity** (`/onboarding`) — the assurance ladder
  (`none → declared → phone_verified → verified`): attest 18+
  (`/v1/identity/tos-accept`), verify a phone bound to the account
  (`/v1/auth/phone/*`), start eKYC (`/v1/identity/verify/begin`), then apply to
  instruct (`/v1/instructor/apply`). After each climb the server re-mints the
  token (`/v1/token/refresh`) so the new tier shows on reload.
- **Catalog** — published classes (`/v1/classes/published`) and live sessions
  (`/v1/sessions`, gated at the declared tier → 403 prompt).
- **Live room** — `/v1/sessions/{id}/join` returns a LiveKit grant; the room
  connects with `livekit-client` directly (no official LiveKit Svelte
  components). Joining is gated at `phone_verified` (the Decree 147 floor).

The screens use plain server-action forms, so the core loop works even without
client JS (the live room is the exception — it needs the browser SDK).

## Run

```sh
npm install
npm run dev          # http://localhost:5173
```

Point the BFF at a running `authd` via `API_BASE` (default
`http://localhost:8080`; see `.env.example`).

```sh
npm run check        # svelte-check (type + a11y)
npm run build        # production build (adapter-node)
```

`adapter-node` is used because the app needs a server at runtime to hold the
token cookies and proxy `authd`.

## End-to-end smoke

```sh
npm run e2e          # web/e2e/run.sh
```

A Playwright test (`e2e/funnel.spec.ts`) drives the real funnel in a browser —
email-OTP sign-in, the first assurance climb (`none → declared`), and the
catalog — against a real `authd` + Postgres. The harness (`e2e/run.sh`) boots the
whole stack: a throwaway Postgres, `authd` with `LAPLAT_DEV_OTP_CONSOLE=1` (the
test reads the code from authd's log, exactly as a developer would), and the
SvelteKit dev server (dev mode so its cookies aren't `Secure` over http). This is
what turns "the frontend compiles" into "the frontend works": writing it first
caught three real bugs (a stale tier after a climb, a catalog crash on a 404
sessions route, and a non-JSON error body the BFF mis-parsed).

The harness targets this project's dev/CI container (PostgreSQL 16 at
`/usr/lib/postgresql/16/bin`, a `postgres` system user, and a Playwright Chromium
under `/opt/pw-browsers`); adjust those paths to run it on a different machine.

## Not yet wired

- **eKYC**: `verify/begin` is surfaced, but the provider isn't wired in local
  dev, so the `verified` tier isn't reachable end-to-end (operator grant via
  `adminctl` still works).
- **Instructor authoring** and **payments**: out of this slice.
