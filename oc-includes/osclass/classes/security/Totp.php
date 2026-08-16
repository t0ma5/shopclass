<?php

/*
 * This file is part of Shopclass (Mindstellar).
 * Copyright (c) 2021-2026 Mindstellar Community
 *
 * Distributed under the GNU General Public License v3.0 or later. See LICENSE.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

namespace mindstellar\security;

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits) as authenticator apps implement it.
 *
 * The secret is a base32 string; the code is the last six digits of the HOTP
 * value for floor(unix_time / 30). Verification accepts the previous and next
 * step as well, so a code typed a second or two after the clock rolls over still
 * works. That window is the whole of the clock-skew budget: widening it further
 * would only give a guessed code more slots to land in.
 */
class Totp
{
    public const PERIOD = 30;

    public const DIGITS = 6;

    /** Steps either side of the current one that still count as valid. */
    public const WINDOW = 1;

    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * A new 160-bit secret, encoded as unpadded base32.
     *
     * @return string
     */
    public static function randomSecret()
    {
        return self::base32Encode(random_bytes(20));
    }

    /**
     * @param string $data raw bytes
     *
     * @return string unpadded base32
     */
    public static function base32Encode($data)
    {
        $binary = '';
        $len    = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $binary .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
        }
        $chunks = str_split($binary, 5);
        $out    = '';
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $out .= self::ALPHABET[bindec($chunk)];
        }

        return $out;
    }

    /**
     * @param string $b32
     *
     * @return string raw bytes (empty when the input has no valid symbols)
     */
    public static function base32Decode($b32)
    {
        $b32    = preg_replace('/[^A-Z2-7]/', '', strtoupper((string)$b32));
        $binary = '';
        $len    = strlen($b32);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::ALPHABET, $b32[$i]);
            if ($pos === false) {
                continue;
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = str_split($binary, 8);
        $out   = '';
        foreach ($bytes as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }

    /**
     * RFC 4226 HOTP truncated to {@see DIGITS} decimal digits.
     *
     * @param string $secretBin
     * @param int    $counter
     *
     * @return string zero-padded decimal code
     */
    public static function hotp($secretBin, $counter)
    {
        $binCounter = pack('N*', 0) . pack('N*', $counter);
        $hash       = hash_hmac('sha1', $binCounter, $secretBin, true);
        $offset     = ord(substr($hash, -1)) & 0x0F;
        $truncated  = unpack('N', substr($hash, $offset, 4));
        $code       = ($truncated[1] & 0x7FFFFFFF) % (10 ** self::DIGITS);

        return str_pad((string)$code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * The code that is valid at $timestamp (default: now).
     *
     * @param string   $secretB32
     * @param int|null $timestamp unix time
     *
     * @return string
     */
    public static function at($secretB32, $timestamp = null)
    {
        $secretBin = self::base32Decode($secretB32);
        if ($secretBin === '') {
            return '';
        }
        $when = $timestamp === null ? time() : (int)$timestamp;

        return self::hotp($secretBin, (int)floor($when / self::PERIOD));
    }

    /**
     * @param string   $secretB32
     * @param string   $code
     * @param int|null $timestamp unix time the code is checked against
     *
     * @return bool
     */
    public static function verify($secretB32, $code, $timestamp = null)
    {
        $code = preg_replace('/\s+/', '', (string)$code);
        if (!preg_match('/^[0-9]{' . self::DIGITS . '}$/', $code)) {
            return false;
        }
        $secretBin = self::base32Decode($secretB32);
        if ($secretBin === '') {
            return false;
        }
        $when  = $timestamp === null ? time() : (int)$timestamp;
        $slice = (int)floor($when / self::PERIOD);
        for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
            if (hash_equals(self::hotp($secretBin, $slice + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * otpauth:// URI an authenticator app can import.
     *
     * @param string $issuer
     * @param string $account
     * @param string $secretB32
     *
     * @return string
     */
    public static function otpauthUri($issuer, $account, $secretB32)
    {
        $issuer  = (string)$issuer;
        $account = (string)$account;
        $label   = rawurlencode($issuer !== '' ? ($issuer . ':' . $account) : $account);

        return 'otpauth://totp/' . $label
            . '?secret=' . rawurlencode($secretB32)
            . '&issuer=' . rawurlencode($issuer)
            . '&period=' . self::PERIOD
            . '&digits=' . self::DIGITS;
    }
}
