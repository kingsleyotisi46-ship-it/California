ALTER TABLE app_users ADD COLUMN IF NOT EXISTS profile_image text;
CREATE TABLE IF NOT EXISTS virtual_wallets (
 user_id uuid PRIMARY KEY REFERENCES app_users(id) ON DELETE RESTRICT,
 balance_cents bigint NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
 currency char(3) NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS virtual_transactions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
 kind text NOT NULL CHECK(kind IN ('virtual_funding','account_transfer')),
 direction text NOT NULL CHECK(direction IN ('credit','debit')),
 amount_cents bigint NOT NULL CHECK(amount_cents > 0),
 currency char(3) NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
 description text NOT NULL,
 reference uuid NOT NULL,
 idempotency_key uuid NOT NULL,
 counterparty_account_number varchar(11),
 created_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT virtual_transactions_user_idempotency_unique UNIQUE(user_id,idempotency_key),
 CONSTRAINT virtual_transactions_reference_user_unique UNIQUE(reference,user_id)
);
CREATE INDEX IF NOT EXISTS virtual_transactions_user_date_idx ON virtual_transactions(user_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS app_users_account_lookup_idx ON app_users(account_number) WHERE account_number IS NOT NULL;
