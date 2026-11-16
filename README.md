# ShiftLab Performance Online

The supplied ShiftLab racing game, adapted for Netlify with required online connectivity. The game opens in multiplayer free roam and retains the garage, tuning, skid pad, drag strip, circuit, and drift modes. A lost server connection pauses simulation and shows a reconnect screen.

The frontend is a self-contained HTML/CSS/Canvas JavaScript game in `public/index.html`. A Node.js 24 Netlify Server handles WebSocket multiplayer and saved progress. Netlify Database stores garage progress, scores, and racer names through Drizzle ORM. An anonymous HttpOnly browser cookie identifies saves; clearing cookies starts a new profile. Saves do not transfer between devices.

## Local development

Use Node.js 24+, run `npm install`, then `netlify dev --port 8889` with the project linked to Netlify. Open the provided local URL in two browser tabs to try multiplayer. Netlify applies database migrations on deployment; do not apply migrations manually. The plain Node start command serves backend routes only; use Netlify Dev to serve the frontend and backend together.

## Deployment and behavior

Netlify publishes `public` and detects `netlify/server/index.mjs` automatically. No frontend build step is required. Multiplayer uses the site's `/ws` endpoint with secure WebSockets under HTTPS. Connection retries use exponential backoff. Active player connections exist for the lifetime of the server process; progress persists in the database.

Player motion and gifts retain the supplied game's client-reported model. This is a casual multiplayer game, not a server-authoritative competitive economy. Voice retains the supplied peer-to-peer implementation and depends on microphone permission and network compatibility. Players on separate server instances do not share a room; a shared relay would be required before scaling to multiple instances.

Changes were reviewed by reading the edited files. Deployment validation and a two-device gameplay check remain necessary before public launch.
