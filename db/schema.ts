import { pgTable, text, jsonb, primaryKey, timestamp } from 'drizzle-orm/pg-core';

export const playerAccounts = pgTable('player_accounts', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  passwordSalt: text('password_salt').notNull(),
  passwordHash: text('password_hash').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const playerSessions = pgTable('player_sessions', {
  tokenHash: text('token_hash').primaryKey(),
  playerId: text('player_id').notNull().references(() => playerAccounts.id, { onDelete: 'cascade' }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const saves = pgTable('saves', {
  playerId: text('player_id').notNull(),
  namespace: text('namespace').notNull(),
  key: text('key').notNull(),
  value: jsonb('value'),
}, (t) => [primaryKey({ columns: [t.playerId, t.namespace, t.key] })]);
