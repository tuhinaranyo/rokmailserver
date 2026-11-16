-- rokmail schema. This file is the CONTRACT between the admin app (writer)
-- and Postfix/Dovecot (readers). Postfix and Dovecot only ever read the
-- `accounts` table and the v_* views below. Do not rename those columns/views.
-- Every statement is idempotent; the admin app runs this file on each start.

CREATE TABLE IF NOT EXISTS domains (
  name       TEXT PRIMARY KEY,               -- lowercase, e.g. rokomari.com
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS departments (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

-- One row per person/mailbox. `email` is always stored lowercase.
CREATE TABLE IF NOT EXISTS accounts (
  id            INTEGER PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  password      TEXT NOT NULL,               -- Dovecot format: {BLF-CRYPT}$2a$...
  role          TEXT NOT NULL DEFAULT 'user'
                CHECK (role IN ('superadmin','admin','helpdesk','user')),
  department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
  quota_mb      INTEGER NOT NULL DEFAULT 1024,
  can_send      INTEGER NOT NULL DEFAULT 1,  -- 0 = receive-only
  forward_to    TEXT NOT NULL DEFAULT '',    -- comma-separated addresses, '' = none
  keep_copy     INTEGER NOT NULL DEFAULT 1,  -- when forwarding, also keep in mailbox
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS accounts_department ON accounts(department_id);

-- Role / shared addresses (career@, support@ ...). Never has a mailbox itself.
CREATE TABLE IF NOT EXISTS aliases (
  id            INTEGER PRIMARY KEY,
  address       TEXT NOT NULL UNIQUE,        -- lowercase; must not equal an account email
  description   TEXT NOT NULL DEFAULT '',
  department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alias_members (
  alias_id    INTEGER NOT NULL REFERENCES aliases(id) ON DELETE CASCADE,
  destination TEXT NOT NULL,                 -- lowercase; local account or external address
  can_send    INTEGER NOT NULL DEFAULT 0,    -- member may send AS the alias address (local accounts only)
  PRIMARY KEY (alias_id, destination)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,               -- sha256 hex of the cookie token
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY,
  at     TEXT NOT NULL DEFAULT (datetime('now')),
  actor  TEXT NOT NULL,                      -- email of who did it ('cli' for CLI)
  action TEXT NOT NULL,                      -- e.g. account.create, account.password, alias.delete
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------------------
-- Views read by the mail stack
-- ---------------------------------------------------------------------------

-- Postfix virtual_alias_maps: SELECT destination FROM v_forward WHERE address='%s'
-- (multiple rows are joined by Postfix; a row may itself be a comma list).
DROP VIEW IF EXISTS v_forward;
CREATE VIEW v_forward AS
  SELECT a.address AS address, m.destination AS destination
    FROM aliases a JOIN alias_members m ON m.alias_id = a.id
   WHERE a.active = 1
  UNION ALL
  SELECT email, email      FROM accounts WHERE active = 1 AND forward_to <> '' AND keep_copy = 1
  UNION ALL
  SELECT email, forward_to FROM accounts WHERE active = 1 AND forward_to <> '';

-- Postfix smtpd_sender_login_maps: SELECT login FROM v_sender WHERE address='%s'
-- Who (SASL login) may use `address` as envelope/From sender.
DROP VIEW IF EXISTS v_sender;
CREATE VIEW v_sender AS
  SELECT email AS address, email AS login
    FROM accounts WHERE active = 1 AND can_send = 1
  UNION ALL
  SELECT a.address, m.destination
    FROM aliases a
    JOIN alias_members m ON m.alias_id = a.id
    JOIN accounts acc    ON acc.email = m.destination
   WHERE a.active = 1 AND m.can_send = 1 AND acc.active = 1 AND acc.can_send = 1;
