-- Change events for the console's live streams: every new log chunk, run
-- change, approval and stack change notifies channel srustiops_events with
-- "<kind>:<id>:<business unit>", so open pages update without polling.
CREATE FUNCTION srustiops_notify_run() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bu text;
BEGIN
  SELECT s.bu INTO bu FROM stacks s WHERE s.id = NEW.stack_id;
  PERFORM pg_notify('srustiops_events', 'run:' || NEW.id || ':' || COALESCE(bu, ''));
  RETURN NULL;
END $$;
CREATE TRIGGER runs_notify AFTER INSERT OR UPDATE OF status, plan_summary, finished_at ON runs
  FOR EACH ROW EXECUTE FUNCTION srustiops_notify_run();

CREATE FUNCTION srustiops_notify_run_child() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bu text;
BEGIN
  SELECT s.bu INTO bu FROM runs r JOIN stacks s ON s.id = r.stack_id WHERE r.id = NEW.run_id;
  PERFORM pg_notify('srustiops_events', TG_ARGV[0] || ':' || NEW.run_id || ':' || COALESCE(bu, ''));
  RETURN NULL;
END $$;
CREATE TRIGGER run_logs_notify AFTER INSERT ON run_logs
  FOR EACH ROW EXECUTE FUNCTION srustiops_notify_run_child('log');
CREATE TRIGGER run_approvals_notify AFTER INSERT ON run_approvals
  FOR EACH ROW EXECUTE FUNCTION srustiops_notify_run_child('run');

CREATE FUNCTION srustiops_notify_stack() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; END IF;
  PERFORM pg_notify('srustiops_events', 'stack:' || r.id || ':' || COALESCE(r.bu, ''));
  RETURN NULL;
END $$;
CREATE TRIGGER stacks_notify AFTER INSERT OR UPDATE OR DELETE ON stacks
  FOR EACH ROW EXECUTE FUNCTION srustiops_notify_stack();

-- Finished runs' logs can move to the tenant bucket; the rows are then gone.
ALTER TABLE runs ADD COLUMN logs_archived boolean NOT NULL DEFAULT false;
