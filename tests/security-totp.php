<?php
/*
 * This file is part of Shopclass (Mindstellar).
 * Copyright (c) 2021-2026 Mindstellar Community
 *
 * Distributed under the GNU General Public License v3.0 or later. See LICENSE.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Unit pins for RFC 6238 TOTP as authenticator apps implement it.
 *
 * DB-free. Usage:  php tests/security-totp.php
 */

require_once __DIR__ . '/../oc-includes/vendor/autoload.php';
require_once __DIR__ . '/lib/harness.php';

use mindstellar\security\Totp;

$GLOBALS['okCount']    = 0;
$GLOBALS['failCount']  = 0;
$GLOBALS['failLabels'] = array();

harness_section('Totp: base32 round-trip');

$raw = 'Hello!';
$b32 = Totp::base32Encode($raw);
pin('known ASCII encodes to JBSWY3DPEHPK3PXP', 'JBSWY3DPEHPK3PXP', $b32);
pin('that encoding decodes back', $raw, Totp::base32Decode($b32));
pin('lowercase and spaces are ignored on decode', $raw, Totp::base32Decode('jbsw y3dp ehpk 3pxp'));

$secret = Totp::randomSecret();
check('randomSecret is non-empty base32', $secret !== '' && preg_match('/^[A-Z2-7]+$/', $secret) === 1);
pin('randomSecret round-trips through base32', Totp::base32Decode($secret), Totp::base32Decode(Totp::base32Encode(Totp::base32Decode($secret))));

harness_section('Totp: RFC 4226 HOTP 6-digit vectors');

// Secret is the ASCII string "12345678901234567890" used by RFC 4226 / 6238.
$rfcSecret = '12345678901234567890';
pin('HOTP counter 0', '755224', Totp::hotp($rfcSecret, 0));
pin('HOTP counter 1', '287082', Totp::hotp($rfcSecret, 1));
pin('HOTP counter 2', '359152', Totp::hotp($rfcSecret, 2));

harness_section('Totp: verify window');

$secretB32 = Totp::base32Encode($rfcSecret);
$now       = 1111111109; // RFC 6238 test time; T = floor(1111111109/30) = 37037036
$code      = Totp::at($secretB32, $now);
check('at() returns 6 digits', preg_match('/^[0-9]{6}$/', $code) === 1);
check('current step verifies', Totp::verify($secretB32, $code, $now));
check('previous step verifies inside the window', Totp::verify($secretB32, Totp::at($secretB32, $now - 30), $now));
check('next step verifies inside the window', Totp::verify($secretB32, Totp::at($secretB32, $now + 30), $now));
check('two steps away does not verify', Totp::verify($secretB32, Totp::at($secretB32, $now - 60), $now) === false);
check('a wrong code does not verify', Totp::verify($secretB32, '000000', $now) === false);
check('a non-numeric code does not verify', Totp::verify($secretB32, 'abcdef', $now) === false);

$uri = Totp::otpauthUri('Shopclass', 'admin', $secretB32);
check('otpauth URI starts with otpauth://totp/', strpos($uri, 'otpauth://totp/') === 0);
check('otpauth URI carries the secret', strpos($uri, 'secret=' . rawurlencode($secretB32)) !== false);

exit(harness_result());
