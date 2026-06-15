-- Migration: Geolocation & Travel Velocity Anomaly Detection
-- Run once against the audit_digi database.
USE audit_digi;

-- Per-login location history. One row per successful password entry that
-- reaches the geo stage. We compare the newest two rows to detect "impossible
-- travel" (moving between locations faster than a plane could fly).
CREATE TABLE IF NOT EXISTS user_logins (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    ip_address  VARCHAR(45),                 -- IPv4 or IPv6
    city        VARCHAR(100),
    country     VARCHAR(100),
    latitude    DECIMAL(10, 7),              -- NULL when location is unverified
    longitude   DECIMAL(10, 7),
    login_time  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Drives the post-login gate. When an anomaly fires we flip this to
-- 'otp_required'; the user can't reach the dashboard until OTP clears it.
ALTER TABLE users
    ADD COLUMN security_status ENUM('ok', 'otp_required') NOT NULL DEFAULT 'ok';
