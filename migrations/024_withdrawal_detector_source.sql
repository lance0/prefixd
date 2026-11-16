-- Migration 024: the bound source of a detector unban's withdrawal.
--
-- A detector unban records the source it withdraws for, so the completion
-- audit and the `detector_unban` metric reason survive whichever path
-- completes the withdrawal: the request itself or reconciliation after an
-- ambiguous delete. NULL for every other withdrawal and for requests made
-- before this migration. Adding a nullable column without a default rewrites
-- no row and holds its lock only for the catalog change; withdrawal_requests
-- is small.
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS detector_source TEXT;
