-- The settings of the collector: one row.

CREATE TABLE collection_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    history_days integer NOT NULL DEFAULT 30 CHECK (history_days BETWEEN 1 AND 3650)
);

INSERT INTO collection_settings DEFAULT VALUES;
