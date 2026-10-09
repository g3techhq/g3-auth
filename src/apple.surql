DEFINE TABLE IF NOT EXISTS apple_challenge TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD IF NOT EXISTS state ON apple_challenge TYPE string;
DEFINE FIELD IF NOT EXISTS nonce ON apple_challenge TYPE string;
DEFINE FIELD IF NOT EXISTS native ON apple_challenge TYPE bool;
DEFINE FIELD IF NOT EXISTS redirect_uri ON apple_challenge TYPE option<string>;
DEFINE FIELD IF NOT EXISTS return_to ON apple_challenge TYPE option<string>;
DEFINE FIELD IF NOT EXISTS expires_at ON apple_challenge TYPE datetime;
DEFINE INDEX IF NOT EXISTS apple_challenge_state_idx ON apple_challenge FIELDS state UNIQUE;
