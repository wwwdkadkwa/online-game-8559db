CREATE TABLE "player_accounts" (
	"id" text PRIMARY KEY,
	"username" text NOT NULL UNIQUE,
	"password_salt" text NOT NULL,
	"password_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "player_sessions" (
	"token_hash" text PRIMARY KEY,
	"player_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "player_sessions" ADD CONSTRAINT "player_sessions_player_id_player_accounts_id_fkey" FOREIGN KEY ("player_id") REFERENCES "player_accounts"("id") ON DELETE CASCADE;