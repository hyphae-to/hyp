-- Leave existing rows unmarked. Source and gate reason are not provenance.
ALTER TABLE mailbox ADD COLUMN daemon_notice TEXT
    CHECK (daemon_notice IN ('system_notice', 'wake_notice'));
