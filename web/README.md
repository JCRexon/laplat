# laplat web

The web client — a Vite + React + TypeScript SPA. First vertical slice: sign in,
climb the assurance ladder, browse the catalog, and join a live session.

## Why a SPA (not Next.js)

The app sits behind a bearer-token API (`authd`): an access token (short-lived)
plus a refresh token. A client-side SPA matches that model directly and lets the
LiveKit web SDK own the room connection, with no SSR layer to reconcile against
the token flow. The public catalog could get an SSR/SEO front later; the authed
loop is cleanest as a SPA.

## What's here

The slice walks the differentiated funnel end to end against the real API:

- **Sign in** — email OTP (`/v1/auth/email/{request,verify}`). In dev the
  console code sender logs the code to authd's output, so no SMTP vendor is
  needed.
- **My identity** — the assurance ladder (`none → declared → phone_verified →
  verified`). Attest 18+ (`/v1/identity/tos-accept`), verify a phone
  (`/v1/auth/phone/*`, bound to the account), start eKYC
  (`/v1/identity/verify/begin`), then apply to instruct
  (`/v1/instructor/apply`). After each climb the token is re-minted
  (`/v1/token/refresh`) so the new tier shows immediately.
- **Catalog** — published classes (`/v1/classes/published`) and live sessions
  (`/v1/sessions`, gated at the declared tier).
- **Live room** — `/v1/sessions/{id}/join` returns a LiveKit grant
  (`{ wsUrl, token }`); the room connects with `@livekit/components-react`.
  Joining is gated at `phone_verified` (the Decree 147 floor).

Token handling (storage + transparent refresh on 401) lives in
`src/api/client.ts`; typed endpoints in `src/api/endpoints.ts`; DTOs mirror the
Go `json:` tags in `src/api/types.ts`.

## Run

```sh
npm install
npm run dev          # http://localhost:5173, proxies /v1 -> VITE_API_TARGET
```

Point the dev proxy at a running `authd` (default `http://localhost:8080`) via
`VITE_API_TARGET` (see `.env.example`). For a deployed build, set
`VITE_API_BASE` to an absolute API origin.

```sh
npm run typecheck    # tsc --noEmit
npm run build        # type-check + production bundle
```

## Not yet wired

- **eKYC**: `verify/begin` is surfaced, but the provider isn't wired in local
  dev, so the `verified` tier isn't reachable end-to-end yet (operator grant via
  `adminctl` still works).
- **Instructor authoring** and **payments**: out of this slice.
