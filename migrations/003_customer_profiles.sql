ALTER TABLE app_users
  ADD COLUMN IF NOT EXISTS first_name text,
  ADD COLUMN IF NOT EXISTS middle_name text,
  ADD COLUMN IF NOT EXISTS last_name text,
  ADD COLUMN IF NOT EXISTS phone_number text,
  ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz,
  ADD COLUMN IF NOT EXISTS account_number varchar(11);

CREATE UNIQUE INDEX IF NOT EXISTS app_users_account_number_unique
  ON app_users(account_number) WHERE account_number IS NOT NULL;

ALTER TABLE app_users
  ADD CONSTRAINT app_users_account_number_format
  CHECK (account_number IS NULL OR account_number ~ '^[0-9]{11}$');

ALTER TABLE app_users
  ADD CONSTRAINT app_users_phone_number_nonempty
  CHECK (phone_number IS NULL OR length(trim(phone_number)) BETWEEN 7 AND 20);
