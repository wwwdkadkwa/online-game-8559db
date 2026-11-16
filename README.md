# ShiftLab Performance Online

The supplied ShiftLab racing game, adapted for Netlify with required online connectivity. The game opens in multiplayer free roam and retains the garage, tuning, skid pad, drag strip, circuit, and drift modes. A lost server connection pauses simulation and shows a reconnect screen.

The frontend is a self-contained HTML/CSS/Canvas JavaScript game in `public/index.html`. A Node.js 24 Netlify Server handles WebSocket multiplayer and saved progress. Netlify Database stores garage progress, scores, and racer names through Drizzle ORM. Players join as guests; progress remains tied to the anonymous browser cookie and does not transfer between browsers. Clearing browser cookies starts a new save profile.

## Local development

Use Node.js 24+, run `npm install`, then `npx netlify-cli@^27.17.0 dev` with the project linked to Netlify. Open the provided local URL in two browser tabs to try multiplayer. Persistent saves require the linked Netlify Database. Netlify applies database migrations on deployment; do not apply migrations manually. Use Netlify Dev rather than the plain Node start command to test the Netlify Server integration locally.

## Deployment and behavior

Netlify publishes `public` and detects `netlify/server/index.mjs` automatically. No frontend build step is required. Multiplayer uses the site's `/ws` endpoint with secure WebSockets under HTTPS. Connection retries use exponential backoff. Active player connections exist for the lifetime of the server process; progress persists in the database.

## Private admin panel

Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` as server environment variables in Netlify (or in the local development environment). Do not put credentials in the HTML or commit them. The F2 admin console uses an HttpOnly session cookie, expires sessions after 12 hours, and enforces admin-only multiplayer actions on the server. Admin sign-in is unavailable until both variables are configured.

The follow-up migration removes the unused player account/session tables and preserves browser-specific saves.

Player motion and gifts retain the supplied game's client-reported model. This is a casual multiplayer game, not a server-authoritative competitive economy. Voice retains the supplied peer-to-peer implementation and depends on microphone permission and network compatibility. Players on separate server instances do not share a room; a shared relay would be required before scaling to multiple instances.

Changes were reviewed by reading the edited files. Deployment validation and a two-device gameplay check remain necessary before public launch.
