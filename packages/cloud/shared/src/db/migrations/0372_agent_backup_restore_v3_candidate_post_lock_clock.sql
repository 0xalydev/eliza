-- Forward-only post-lock expiry fences for restore-v3 candidate authorization
-- and seal. PostgreSQL executes same-event triggers in name order, so these
-- `zz_` guards run after 0371's canonical lock-order/transition triggers while
-- retaining every lock until the INSERT statement completes.

CREATE OR REPLACE FUNCTION "guard_agent_backup_restore_v3_seal_auth_post_lock_clock"()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."expires_at" <= clock_timestamp() THEN
    RAISE EXCEPTION 'restore-v3 seal authorization expired after authority locks'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS "zz_agent_backup_restore_v3_seal_auth_post_lock_clock_guard"
  ON "agent_backup_restore_v3_candidate_seal_authorizations";
--> statement-breakpoint
CREATE TRIGGER "zz_agent_backup_restore_v3_seal_auth_post_lock_clock_guard"
  BEFORE INSERT ON "agent_backup_restore_v3_candidate_seal_authorizations"
  FOR EACH ROW EXECUTE FUNCTION
    "guard_agent_backup_restore_v3_seal_auth_post_lock_clock"();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION "guard_agent_backup_restore_v3_terminal_post_lock_clock"()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  authorization_expires_at timestamptz;
BEGIN
  IF NEW."command_kind" = 'seal' THEN
    SELECT seal_auth."expires_at" INTO authorization_expires_at
    FROM "agent_backup_restore_v3_candidate_seal_authorizations" AS seal_auth
    WHERE seal_auth."id" = NEW."authorization_id"
      AND seal_auth."candidate_id" = NEW."candidate_id"
      AND seal_auth."proof_token_sha256" = NEW."proof_token_sha256"
      AND seal_auth."candidate_receipt_sha256" = NEW."sealed_receipt_sha256";
    IF NOT FOUND OR authorization_expires_at <= clock_timestamp() THEN
      RAISE EXCEPTION 'restore-v3 seal authorization expired after terminal locks'
        USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS "zz_agent_backup_restore_v3_terminal_post_lock_clock_guard"
  ON "agent_backup_restore_v3_candidate_terminal_commands";
--> statement-breakpoint
CREATE TRIGGER "zz_agent_backup_restore_v3_terminal_post_lock_clock_guard"
  BEFORE INSERT ON "agent_backup_restore_v3_candidate_terminal_commands"
  FOR EACH ROW EXECUTE FUNCTION "guard_agent_backup_restore_v3_terminal_post_lock_clock"();
