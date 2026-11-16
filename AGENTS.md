# Project architecture

This project adapts the supplied ShiftLab Performance HTML game. Preserve its game mechanics and visual design when making focused changes.

- `public/index.html`: Canvas renderer, simulation, garage, audio, multiplayer client, connection overlay, and asynchronous save adapter.
- `netlify/server/index.mjs`: exported Node HTTP server with attached `ws` server at `/ws`, anonymous session endpoint, and persistent save endpoints.
- `db/schema.ts`: source of truth for persistent saves.
- `drizzle.config.ts`: migration generator configuration.
- `netlify/database/migrations`: generated migrations applied by Netlify during deployment.

Use Node.js 24 and ESM server modules. Keep the HTML game's existing conventions for minimal diffs. The required online connection must remain active across game modes; simulation must pause whenever the server has not acknowledged the player. Preserve automatic reconnection, and rebuild roster state after every reconnect.

Only active socket membership and transient vehicle state belong in server memory. Store persistent progress in Netlify Database. Saves are anonymous and browser-specific, not authenticated accounts. Never expose the session cookie to JavaScript. Keep API queries parameterized, size-limit writes, and allowlist save namespaces.

Generate named migrations after editing the Drizzle schema; never apply migrations manually. Multiplayer physics and gifts are client-reported. Cross-instance multiplayer and authoritative economy changes require explicit architecture work, rather than assuming the socket map is global.
