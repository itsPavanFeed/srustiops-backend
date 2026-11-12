-- The platform root: exactly one recovery account with one live credential,
-- for when sign-in through SSO is unavailable. Everyone else, other platform
-- admins included, signs in with SSO. The first platform admin becomes root;
-- older bootstrap runs may have left it several tokens, so only the newest
-- live one is kept.
ALTER TABLE users ADD COLUMN platform_root boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD CONSTRAINT users_root_is_admin CHECK (NOT platform_root OR platform_admin);
UPDATE users SET platform_root = true
 WHERE id = (SELECT id FROM users WHERE platform_admin ORDER BY created_at, id LIMIT 1);
CREATE UNIQUE INDEX users_one_platform_root ON users ((true)) WHERE platform_root;
UPDATE api_tokens SET revoked_at = now()
 WHERE revoked_at IS NULL
   AND user_id = (SELECT id FROM users WHERE platform_root)
   AND id <> (SELECT id FROM api_tokens WHERE user_id = (SELECT id FROM users WHERE platform_root)
               AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1);
