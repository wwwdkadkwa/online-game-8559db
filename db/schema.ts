import { pgTable, text, jsonb, primaryKey, timestamp } from 'drizzle-orm/pg-core';

export const saves = pgTable('saves', {
  playerId: text('player_id').notNull(),
  namespace: text('namespace').notNull(),
  key: text('key').notNull(),
  value: jsonb('value'),
}, (t) => [primaryKey({ columns: [t.playerId, t.namespace, t.key] })]);
