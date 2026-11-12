-- The issuer the client's trust role was made for (recorded when it was
-- verified), and the latest re-check from the console.
ALTER TABLE provisionings ADD COLUMN trust_issuer text NOT NULL DEFAULT '';
ALTER TABLE provisionings ADD COLUMN trust_check jsonb;
