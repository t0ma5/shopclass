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

use Cookie;
use Params;
use Session;

/**
 * Optional authenticator-app 2FA for oc-admin, challenged only when the login IP changes.
 *
 * This is a weaker guarantee than prompting on every login: it is a deliberate
 * UX choice (password-only on the usual address, code when the address moves).
 * It is not a substitute for always-on 2FA.
 *
 * currentIp() is REMOTE_ADDR only, same rule as {@see LoginThrottle}. A
 * forwarded-for header is client-controlled. Behind Cloudflare or any reverse
 * proxy that does not restore the visitor address onto REMOTE_ADDR, every admin
 * resolves to the same proxy IP: after the first successful challenge, the
 * stored last IP matches forever and 2FA becomes a no-op for later password
 * theft from that same edge. Shared NAT (cafes, CGNAT) re-prompts because the
 * address keeps changing.
 *
 * Enrollment is per administrator, on their own profile. Remember-me from a new
 * IP takes the same path — the cookie is not treated as a full login until the
 * code succeeds. A consumed TOTP time-step is recorded so the same code cannot
 * be replayed inside the verification window.
 *
 * Secrets are AES-256-GCM (12-byte IV, 16-byte tag, base64 in the VARCHAR)
 * keyed from {@see SigningKey}. Backup codes are stored hashed and consumed
 * on use. A password change clears the last IP, so the next sign-in from
 * anywhere has to 2FA once.
 *
 * The table arrives with migration 0036 / struct.sql. If it is not there yet
 * (files deployed, upgrade not run) every lookup fails open: 2FA is treated as
 * off, so the administrator who has to start the upgrade is not locked out.
 */
class AdminTotp
{
    private const PENDING_TTL = 300;

    /**
     * @return string
     */
    public static function table()
    {
        return DB_TABLE_PREFIX . 't_admin_2fa';
    }

    /**
     * REMOTE_ADDR only, same rule as {@see LoginThrottle}. See the class comment
     * for what that means behind a reverse proxy.
     *
     * @return string
     */
    public static function currentIp()
    {
        return (string)Params::getServerParam('REMOTE_ADDR');
    }

    /**
     * @param int $adminId
     *
     * @return array|null
     */
    public static function load($adminId)
    {
        $adminId = (int)$adminId;
        if ($adminId <= 0) {
            return null;
        }
        try {
            $row = osc_db_select_one(
                'SELECT * FROM ' . self::table() . ' WHERE fk_i_admin_id = ?',
                array($adminId)
            );
        } catch (\Throwable $e) {
            return null;
        }

        return is_array($row) && isset($row['fk_i_admin_id']) ? $row : null;
    }

    /**
     * @param int $adminId
     *
     * @return bool
     */
    public static function isEnabled($adminId)
    {
        $row = self::load($adminId);

        return $row && (int)$row['b_enabled'] === 1 && $row['s_secret'] !== '';
    }

    /**
     * @param int $adminId
     *
     * @return bool
     */
    public static function needsChallenge($adminId)
    {
        if (!self::isEnabled($adminId)) {
            return false;
        }
        $row  = self::load($adminId);
        $last = isset($row['s_last_ip']) ? trim((string)$row['s_last_ip']) : '';
        $now  = self::currentIp();
        if ($last === '' || $now === '') {
            return true;
        }

        return strcasecmp($last, $now) !== 0;
    }

    /**
     * @param int   $adminId
     * @param array $fields
     *
     * @return bool
     */
    public static function save($adminId, $fields)
    {
        $adminId = (int)$adminId;
        if ($adminId <= 0 || !is_array($fields) || $fields === array()) {
            return false;
        }
        try {
            $existing = self::load($adminId);
            if ($existing) {
                osc_db_table(self::table())->where('fk_i_admin_id', $adminId)->update($fields);

                return true;
            }
            $fields['fk_i_admin_id'] = $adminId;
            osc_db_table(self::table())->insert($fields);

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * @param int $adminId
     *
     * @return void
     */
    public static function touchIp($adminId)
    {
        self::save($adminId, array(
            's_last_ip'      => self::currentIp(),
            'dt_last_verify' => date('Y-m-d H:i:s'),
        ));
    }

    /**
     * Forget the last verified IP so the next sign-in must 2FA. Called after a
     * password change: the password is the other factor, and it just moved.
     *
     * @param int $adminId
     *
     * @return void
     */
    public static function clearLastIp($adminId)
    {
        if (!self::isEnabled($adminId)) {
            return;
        }
        self::save($adminId, array('s_last_ip' => ''));
    }

    /**
     * @param string $plain base32 TOTP secret
     *
     * @return string base64(IV . tag . ciphertext), or empty on failure
     */
    public static function encrypt($plain)
    {
        $plain = (string)$plain;
        if ($plain === '') {
            return '';
        }
        $iv  = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plain,
            'aes-256-gcm',
            self::cryptoKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );
        if ($ciphertext === false || strlen($tag) !== 16) {
            return '';
        }

        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * @param string $stored base64 from encrypt()
     *
     * @return string
     */
    public static function decrypt($stored)
    {
        $stored = (string)$stored;
        if ($stored === '') {
            return '';
        }
        $raw = base64_decode($stored, true);
        if ($raw === false || strlen($raw) <= 28) {
            return '';
        }
        $plain = openssl_decrypt(
            substr($raw, 28),
            'aes-256-gcm',
            self::cryptoKey(),
            OPENSSL_RAW_DATA,
            substr($raw, 0, 12),
            substr($raw, 12, 16)
        );

        return $plain === false ? '' : (string)$plain;
    }

    /**
     * @return string 32-byte AES key
     */
    private static function cryptoKey()
    {
        return hash('sha256', SigningKey::get() . '|admin-totp-v1', true);
    }

    /**
     * @return array<int, string> eight 8-character codes
     */
    public static function generateBackupCodes()
    {
        $codes = array();
        for ($i = 0; $i < 8; $i++) {
            $codes[] = strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
        }

        return $codes;
    }

    /**
     * @param array<int, string> $codes
     *
     * @return string JSON of password_hash() values
     */
    public static function hashBackupCodes($codes)
    {
        $hashes = array();
        foreach ($codes as $code) {
            $hashes[] = password_hash($code, PASSWORD_DEFAULT);
        }

        return json_encode($hashes);
    }

    /**
     * Consume one unused backup code. Returns true and rewrites the remaining
     * hashes when it matches; false leaves the row alone.
     *
     * @param int    $adminId
     * @param string $code
     *
     * @return bool
     */
    public static function consumeBackupCode($adminId, $code)
    {
        $code = strtoupper(preg_replace('/[^A-Z0-9]/', '', (string)$code));
        if (strlen($code) < 8) {
            return false;
        }
        $row = self::load($adminId);
        if (!$row || empty($row['s_backup_codes'])) {
            return false;
        }
        $hashes = json_decode($row['s_backup_codes'], true);
        if (!is_array($hashes)) {
            return false;
        }
        $matched = false;
        $keep    = array();
        foreach ($hashes as $hash) {
            if (!$matched && password_verify($code, $hash)) {
                $matched = true;
                continue;
            }
            $keep[] = $hash;
        }
        if (!$matched) {
            return false;
        }
        self::save($adminId, array('s_backup_codes' => json_encode($keep)));

        return true;
    }

    /**
     * TOTP or a backup code.
     *
     * @param int    $adminId
     * @param string $code
     *
     * @return bool
     */
    public static function verifyAny($adminId, $code)
    {
        $row = self::load($adminId);
        if (!$row || (int)$row['b_enabled'] !== 1) {
            return false;
        }
        $secret = self::decrypt($row['s_secret']);
        if ($secret !== '') {
            $step = Totp::matchingSlice($secret, $code);
            if ($step !== null) {
                $last = isset($row['i_last_totp_step']) ? (int)$row['i_last_totp_step'] : 0;
                if ($last > 0 && $step <= $last) {
                    return false;
                }
                self::save($adminId, array('i_last_totp_step' => $step));

                return true;
            }
        }

        return self::consumeBackupCode($adminId, $code);
    }

    /**
     * @return void
     */
    public static function clearPending()
    {
        $sess = Session::newInstance();
        $sess->_drop('admin_totp_id');
        $sess->_drop('admin_totp_locale');
        $sess->_drop('admin_totp_remember');
        $sess->_drop('admin_totp_redirect');
        $sess->_drop('admin_totp_until');
        $sess->_drop('admin_totp_from_cookie');
    }

    /**
     * @return array{id:int,locale:string,remember:bool,redirect:string,from_cookie:bool}|null
     */
    public static function pending()
    {
        $sess  = Session::newInstance();
        $id    = (int)$sess->_get('admin_totp_id');
        $until = (int)$sess->_get('admin_totp_until');
        if ($id <= 0) {
            return null;
        }
        if ($until > 0 && time() > $until) {
            self::clearPending();

            return null;
        }

        return array(
            'id'          => $id,
            'locale'      => (string)$sess->_get('admin_totp_locale'),
            'remember'    => (int)$sess->_get('admin_totp_remember') === 1,
            'redirect'    => (string)$sess->_get('admin_totp_redirect'),
            'from_cookie' => (int)$sess->_get('admin_totp_from_cookie') === 1,
        );
    }

    /**
     * Record a password-verified admin who still owes a TOTP. Starts a session
     * (the first write does) so the pending state survives the redirect to the
     * code form. Re-entry for the same admin is a no-op, so a remember-me hit
     * that races the login form does not reset the five-minute timer.
     *
     * @param array $admin row from t_admin
     * @param array $opts  locale, remember, redirect, from_cookie
     *
     * @return void
     */
    public static function beginPending($admin, $opts)
    {
        if (!is_array($admin) || empty($admin['pk_i_id'])) {
            return;
        }
        $pending = self::pending();
        if ($pending && (int)$pending['id'] === (int)$admin['pk_i_id']) {
            return;
        }
        $sess = Session::newInstance();
        $sess->_set('admin_totp_id', (int)$admin['pk_i_id']);
        $sess->_set('admin_totp_locale', isset($opts['locale']) ? (string)$opts['locale'] : '');
        $sess->_set('admin_totp_remember', !empty($opts['remember']) ? 1 : 0);
        $sess->_set('admin_totp_redirect', isset($opts['redirect']) ? (string)$opts['redirect'] : '');
        $sess->_set('admin_totp_until', time() + self::PENDING_TTL);
        $sess->_set('admin_totp_from_cookie', !empty($opts['from_cookie']) ? 1 : 0);
    }

    /**
     * Establish the admin session after password (and TOTP, when required).
     *
     * @param array  $admin
     * @param string $locale
     * @param bool   $remember
     *
     * @return void
     */
    public static function establishSession($admin, $locale, $remember)
    {
        if (!is_array($admin) || empty($admin['pk_i_id'])) {
            return;
        }
        $locale          = (string)$locale;
        $is_valid_locale = osc_validate_locale($locale, true);
        if ($is_valid_locale !== true) {
            $locale = osc_admin_language();
        }

        if ($remember) {
            Cookie::newInstance()->set_expires(osc_time_cookie());
            Cookie::newInstance()->push('oc_adminId', $admin['pk_i_id']);
            Cookie::newInstance()->push(
                'oc_adminSecret',
                RememberMe::issue(
                    'admin',
                    $admin['pk_i_id'],
                    $admin['s_password'],
                    osc_time_cookie()
                )
            );
            Cookie::newInstance()->push('oc_adminLocale', $locale);
            Cookie::newInstance()->set();
        }

        Session::newInstance()->_set('adminId', $admin['pk_i_id']);
        Session::newInstance()->_set('adminUserName', $admin['s_username']);
        Session::newInstance()->_set('adminName', $admin['s_name']);
        Session::newInstance()->_set('adminEmail', $admin['s_email']);
        Session::newInstance()->_set('adminLocale', $locale);

        if (self::isEnabled($admin['pk_i_id'])) {
            self::touchIp($admin['pk_i_id']);
        }

        self::clearPending();
        osc_run_hook('login_admin', $admin);
    }

    /**
     * Drop the remember-me cookies. Used when the administrator cancels a 2FA
     * challenge that was started from a cookie restore.
     *
     * @return void
     */
    public static function clearRememberCookies()
    {
        Cookie::newInstance()->pop('oc_adminId');
        Cookie::newInstance()->pop('oc_adminSecret');
        Cookie::newInstance()->pop('oc_adminLocale');
        Cookie::newInstance()->set();
    }

    /**
     * otpauth URI labelled with the site title.
     *
     * @param string $username
     * @param string $secretB32
     *
     * @return string
     */
    public static function otpauthUri($username, $secretB32)
    {
        $issuer = (string)osc_page_title();
        if ($issuer === '') {
            $issuer = 'Shopclass';
        }

        return Totp::otpauthUri($issuer, (string)$username, $secretB32);
    }
}
