-- An environment can use several cloud connections (e.g. ten projects that
-- all serve "dev"), and a connection belongs to at most one environment.
-- Each stack records which of its environment's connections it deploys to.
ALTER TABLE cloud_connections ADD COLUMN environment_id uuid REFERENCES environments(id) ON DELETE SET NULL;
UPDATE cloud_connections c SET environment_id = (
    SELECT e.id FROM environments e WHERE e.connection_id = c.id ORDER BY e.created_at LIMIT 1);
ALTER TABLE stacks ADD COLUMN connection_id uuid REFERENCES cloud_connections(id);
UPDATE stacks s SET connection_id = e.connection_id FROM environments e
 WHERE e.id = s.environment_id AND e.connection_id IS NOT NULL
   AND EXISTS (SELECT 1 FROM cloud_connections c WHERE c.id = e.connection_id AND c.environment_id = e.id);
ALTER TABLE environments DROP COLUMN connection_id;
CREATE INDEX cloud_connections_env ON cloud_connections (environment_id);
