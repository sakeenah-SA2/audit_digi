<?php
/**
 * Step-Up Authentication middleware.
 *
 * Include this file and call requireStepUp() at the top of any high-risk page,
 * AFTER session_start() and your normal "is the user logged in?" check.
 *
 * It guarantees the user has re-entered their password within the last
 * $windowSeconds (default 5 minutes). If not, it bounces them to
 * verify-password.php and remembers where they were heading.
 */
function requireStepUp(int $windowSeconds = 300): void
{
    $verifiedAt = $_SESSION['step_up_verified_at'] ?? 0;

    // Fresh enough? Let them through.
    if (is_int($verifiedAt) && (time() - $verifiedAt) <= $windowSeconds) {
        return;
    }

    // Stale or never verified -> remember the intended destination so we can
    // return the user there after they re-authenticate. We store only the path
    // + query (not a full URL) to avoid open-redirect abuse later.
    $_SESSION['step_up_redirect'] = $_SERVER['REQUEST_URI'] ?? 'dashboard.php';

    header('Location: verify-password.php');
    exit;
}

/**
 * Validates a stored redirect target is a safe, local path.
 * Blocks absolute URLs (//evil.com, http://...) to prevent open redirects.
 */
function safeLocalRedirect(?string $target, string $fallback = 'dashboard.php'): string
{
    if (!$target) {
        return $fallback;
    }
    // Reject anything with a scheme or a leading slash-pair (protocol-relative).
    if (preg_match('#^(https?:)?//#i', $target) || strpos($target, "\\") !== false) {
        return $fallback;
    }
    // Must look like a local script path, optionally with a query string.
    return $target;
}
