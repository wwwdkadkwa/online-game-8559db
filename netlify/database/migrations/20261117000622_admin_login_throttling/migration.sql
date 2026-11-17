CREATE TABLE "admin_login_attempts" (
	"address_hash" text PRIMARY KEY,
	"attempts" integer NOT NULL,
	"reset_at" timestamp with time zone NOT NULL
);
