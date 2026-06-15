-- Migration: Adaptive Account Lockout support
-- Run this once against the audit_digi database.
USE audit_digi;

ALTER TABLE users
    -- Running count of consecutive failed logins. Reset to 0 on success.
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
    -- Timestamp until which logins are refused. NULL = not locked.
    ADD COLUMN locked_until DATETIME NULL DEFAULT NULL;
