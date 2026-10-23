CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS app_users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL,
 password_hash text NOT NULL, status text NOT NULL DEFAULT 'active'
 CHECK(status IN ('active','locked','closed')), email_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT app_users_email_normalized CHECK(email=lower(email)));
CREATE UNIQUE INDEX IF NOT EXISTS app_users_email_unique ON app_users(email);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS banking_customers (
 user_id uuid PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
 provider text NOT NULL CHECK(provider='unit'), provider_customer_id text UNIQUE,
 onboarding_status text NOT NULL DEFAULT 'not_started'
 CHECK(onboarding_status IN ('not_started','pending','approved','denied','needs_information')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS bank_accounts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
 provider text NOT NULL CHECK(provider='unit'), provider_account_id text NOT NULL UNIQUE,
 account_type text NOT NULL, status text NOT NULL, currency char(3) NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
 available_balance_cents bigint, current_balance_cents bigint, last_synced_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS bank_accounts_user_idx ON bank_accounts(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS bank_transactions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
 account_id uuid NOT NULL REFERENCES bank_accounts(id) ON DELETE RESTRICT, provider text NOT NULL CHECK(provider='unit'),
 provider_transaction_id text NOT NULL UNIQUE, amount_cents bigint NOT NULL,
 currency char(3) NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
 direction text NOT NULL CHECK(direction IN ('credit','debit')), status text NOT NULL,
 description text NOT NULL DEFAULT '', effective_at timestamptz, provider_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS bank_transactions_user_date_idx ON bank_transactions(user_id,effective_at DESC NULLS LAST,created_at DESC);
CREATE TABLE IF NOT EXISTS idempotency_keys (
 user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE, key text NOT NULL, request_hash text NOT NULL,
 response_status integer, response_body jsonb, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,key));
CREATE TABLE IF NOT EXISTS security_audit_events (
 id bigserial PRIMARY KEY, user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
 event_type text NOT NULL, request_id text, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS security_audit_created_idx ON security_audit_events(created_at DESC);
CREATE TABLE IF NOT EXISTS provider_webhook_events (
 provider text NOT NULL CHECK(provider='unit'), provider_event_id text NOT NULL, event_type text NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), processed_at timestamptz, processing_error text,
 PRIMARY KEY(provider,provider_event_id));