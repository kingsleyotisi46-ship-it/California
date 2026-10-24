ALTER TABLE provider_webhook_events
  ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS provider_webhook_unprocessed_idx
  ON provider_webhook_events(received_at)
  WHERE processed_at IS NULL;