-- Existing keys retain their explicit resource grants; global access is opt-in.
ALTER TABLE api_keys ADD COLUMN all_projects boolean NOT NULL DEFAULT false;
