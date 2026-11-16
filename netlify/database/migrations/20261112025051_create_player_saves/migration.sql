CREATE TABLE "saves" (
	"player_id" text,
	"namespace" text,
	"key" text,
	"value" jsonb,
	CONSTRAINT "saves_pkey" PRIMARY KEY("player_id","namespace","key")
);
