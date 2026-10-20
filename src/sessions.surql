DEFINE TABLE IF NOT EXISTS sessions TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;

DEFINE FIELD IF NOT EXISTS sessionstore ON sessions TYPE string;
DEFINE FIELD IF NOT EXISTS sessionexpires ON sessions TYPE string;
DEFINE FIELD IF NOT EXISTS sessionid ON sessions TYPE string;

DEFINE INDEX IF NOT EXISTS sessionid_idx ON sessions FIELDS sessionid UNIQUE;

-- Opt-in account tracking must load this schema before enabling the pool.
DEFINE FIELD IF NOT EXISTS session_account ON sessions TYPE option<record>;
-- An older writer replaces CONTENT without this field; absence must remain
-- writable and count as unindexed until all writers have been upgraded.
DEFINE FIELD IF NOT EXISTS account_indexed ON sessions TYPE option<bool> DEFAULT false;
DEFINE INDEX IF NOT EXISTS session_account_idx ON sessions FIELDS session_account;
DEFINE INDEX IF NOT EXISTS session_unindexed_idx ON sessions FIELDS account_indexed;

-- A permanent retirement fence prevents a delayed response from storing an
-- account-bearing session again after the account's sessions were removed.
DEFINE TABLE IF NOT EXISTS auth_session_subject SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD IF NOT EXISTS account ON auth_session_subject TYPE record;
DEFINE FIELD IF NOT EXISTS retired ON auth_session_subject TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS touched_at ON auth_session_subject TYPE datetime DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS session_subject_account_idx ON auth_session_subject FIELDS account UNIQUE;
