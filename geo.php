<?php
/**
 * Geolocation & Travel Velocity (Impossible Travel) Anomaly Detection.
 *
 * Pure helper functions — no output, no session work. Include this in login.php
 * and call the functions from the "password correct" branch.
 */

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

// On localhost your IP is 127.0.0.1, which has no real geolocation. Turn this
// ON to feed the detector hardcoded coordinates so you can prove the maths.
//   Test it: visit  login.php?mock_loc=lagos    then log in,
//            visit  login.php?mock_loc=newyork  and log in again immediately.
//   Lagos -> New York is ~8,400 km. Done seconds apart, the required speed is
//   millions of km/h, so the second login MUST trip the anomaly.
// Set to false in any real deployment so live IP lookups are used.
define('GEO_MOCK_MODE', true);

// Speed (km/h) above which travel is considered physically impossible.
// ~900 km/h is commercial-airliner cruise speed.
define('IMPOSSIBLE_SPEED_KMH', 900);

// Ignore hops shorter than this. Stops GPS/IP jitter in the same city from
// producing a huge "speed" when two logins happen seconds apart.
define('MIN_DISTANCE_KM', 50);

// Hardcoded coordinates for mock mode.
$GLOBALS['GEO_MOCK_LOCATIONS'] = [
    'lagos'   => ['city' => 'Lagos',    'country' => 'Nigeria',       'lat' => 6.5244,  'lon' => 3.3792],
    'newyork' => ['city' => 'New York', 'country' => 'United States', 'lat' => 40.7128, 'lon' => -74.0060],
    'london'  => ['city' => 'London',   'country' => 'United Kingdom','lat' => 51.5074, 'lon' => -0.1278],
];

// ---------------------------------------------------------------------------
// 1. GEOLOCATION LOOKUP
// ---------------------------------------------------------------------------

/**
 * Resolve an IP to { city, country, lat, lon, verified }.
 *
 * SECURITY NOTE: if the lookup fails we DO NOT block the user. We return a
 * record with verified=false and NULL coordinates. The login is allowed but
 * marked "unverified location", so a flaky third-party API can never lock
 * legitimate users out. Anomaly detection simply skips unverifiable logins.
 */
function geoLookup(string $ip): array
{
    // --- Mock mode: ignore the IP, return a chosen city. ---
    if (GEO_MOCK_MODE) {
        $key = $_GET['mock_loc'] ?? 'lagos';
        $loc = $GLOBALS['GEO_MOCK_LOCATIONS'][$key]
            ?? $GLOBALS['GEO_MOCK_LOCATIONS']['lagos'];
        return [
            'city'     => $loc['city'],
            'country'  => $loc['country'],
            'lat'      => $loc['lat'],
            'lon'      => $loc['lon'],
            'verified' => true,
        ];
    }

    // --- Live lookup via ip-api.com (free, no key, ~45 req/min). ---
    $url = "http://ip-api.com/json/" . urlencode($ip)
         . "?fields=status,message,city,country,lat,lon";

    // 3-second timeout so a slow API never hangs the login page.
    $context = stream_context_create(['http' => ['timeout' => 3]]);
    $raw = @file_get_contents($url, false, $context); // @ = swallow network warnings

    if ($raw !== false) {
        $data = json_decode($raw, true);
        if (is_array($data) && ($data['status'] ?? '') === 'success') {
            return [
                'city'     => $data['city']    ?? 'Unknown',
                'country'  => $data['country'] ?? 'Unknown',
                'lat'      => (float) $data['lat'],
                'lon'      => (float) $data['lon'],
                'verified' => true,
            ];
        }
    }

    // Graceful failure: allow login, but coordinates are unknown.
    return [
        'city'     => 'Unknown',
        'country'  => 'Unverified',
        'lat'      => null,
        'lon'      => null,
        'verified' => false,
    ];
}

// ---------------------------------------------------------------------------
// 2. HAVERSINE DISTANCE
// ---------------------------------------------------------------------------

/**
 * Great-circle distance between two lat/lon points, in kilometres.
 * The Haversine formula accounts for the Earth's curvature.
 */
function haversineKm(float $lat1, float $lon1, float $lat2, float $lon2): float
{
    $earthRadiusKm = 6371;

    $dLat = deg2rad($lat2 - $lat1);
    $dLon = deg2rad($lon2 - $lon1);

    $a = sin($dLat / 2) ** 2
       + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) ** 2;

    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));

    return $earthRadiusKm * $c;
}

// ---------------------------------------------------------------------------
// 3. IMPOSSIBLE TRAVEL DETECTION
// ---------------------------------------------------------------------------

/**
 * Compare the current login location against the user's most recent recorded
 * login and decide whether the implied travel speed is physically impossible.
 *
 * Returns an associative array describing the decision (always 'anomaly' key).
 */
function detectImpossibleTravel(PDO $pdo, int $userId, array $current): array
{
    // Can't reason about an unverified current location — let it pass.
    if (empty($current['verified']) || $current['lat'] === null) {
        return ['anomaly' => false, 'reason' => 'current location unverified'];
    }

    // Most recent PRIOR login that actually has coordinates.
    $stmt = $pdo->prepare(
        "SELECT latitude, longitude, login_time, city, country
         FROM user_logins
         WHERE user_id = ? AND latitude IS NOT NULL
         ORDER BY login_time DESC
         LIMIT 1"
    );
    $stmt->execute([$userId]);
    $last = $stmt->fetch();

    // First-ever geolocated login — nothing to compare against.
    if (!$last) {
        return ['anomaly' => false, 'reason' => 'no previous login'];
    }

    // Distance between the two locations.
    $distanceKm = haversineKm(
        (float) $last['latitude'], (float) $last['longitude'],
        (float) $current['lat'],   (float) $current['lon']
    );

    // Time elapsed, using native DateTime objects.
    $lastTime = new DateTime($last['login_time']);
    $now      = new DateTime();
    $seconds  = $now->getTimestamp() - $lastTime->getTimestamp();

    // Guard against zero/negative elapsed time (clock skew or same-second test):
    // treat anything under a second as one second so we never divide by zero.
    $hours = max($seconds, 1) / 3600;

    // Required speed to cover that distance in that time.
    $speedKmh = $distanceKm / $hours;

    // Anomaly only if the hop is meaningful AND faster than a plane.
    $anomaly = ($distanceKm >= MIN_DISTANCE_KM) && ($speedKmh > IMPOSSIBLE_SPEED_KMH);

    return [
        'anomaly'     => $anomaly,
        'reason'      => $anomaly ? 'impossible travel velocity' : 'within plausible speed',
        'distance_km' => round($distanceKm, 1),
        'hours'       => round($hours, 4),
        'speed_kmh'   => round($speedKmh, 1),
        'from'        => $last['city'] . ', ' . $last['country'],
        'to'          => $current['city'] . ', ' . $current['country'],
    ];
}

// ---------------------------------------------------------------------------
// 4. RECORD A LOGIN LOCATION
// ---------------------------------------------------------------------------

/**
 * Persist the current login's location (prepared statement — no injection).
 */
function recordLogin(PDO $pdo, int $userId, string $ip, array $geo): void
{
    $stmt = $pdo->prepare(
        "INSERT INTO user_logins (user_id, ip_address, city, country, latitude, longitude, login_time)
         VALUES (?, ?, ?, ?, ?, ?, NOW())"
    );
    $stmt->execute([
        $userId,
        $ip,
        $geo['city'],
        $geo['country'],
        $geo['lat'],   // may be NULL when unverified
        $geo['lon'],
    ]);
}
