-- The mailbox owns delivery state and deduplication. Dropping the obsolete history
-- table also removes its associated indexes.
DROP TABLE deliveries;
