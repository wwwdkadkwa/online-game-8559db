import { pgTable, text, jsonb, integer, primaryKey, timestamp } from 'drizzle-orm/pg-core';

export const saves = pgTable('saves', {
  playerId: text('player_id').notNull(),
  namespace: text('namespace').notNull(),
  key: text('key').notNull(),
  value: jsonb('value'),
}, (t) => [primaryKey({ columns: [t.playerId, t.namespace, t.key] })]);

export const adminUsers = pgTable('admin_users', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  passwordSalt: text('password_salt').notNull(),
  passwordHash: text('password_hash').notNull(),
  role: text('role').notNull(),
  createdBy: text('created_by').references(() => adminUsers.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const adminSessions = pgTable('admin_sessions', {
  tokenHash: text('token_hash').primaryKey(),
  adminId: text('admin_id').notNull().references(() => adminUsers.id, { onDelete: 'cascade' }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const adminAuditLogs = pgTable('admin_audit_logs', {
  id: text('id').primaryKey(),
  adminId: text('admin_id').references(() => adminUsers.id, { onDelete: 'set null' }),
  username: text('username').notNull(),
  action: text('action').notNull(),
  details: jsonb('details'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const adminLoginAttempts = pgTable('admin_login_attempts', {
  addressHash: text('address_hash').primaryKey(),
  attempts: integer('attempts').notNull(),
  resetAt: timestamp('reset_at', { withTimezone: true }).notNull(),
});
