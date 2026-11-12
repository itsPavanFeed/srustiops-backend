-- Backups are stored as sealed parts (key.part-0001 ...), so no single
-- object has to hold a whole workspace. 0 = one object at key (older backups).
ALTER TABLE backups ADD COLUMN parts int NOT NULL DEFAULT 0;
