<?php
/*
 * This file is part of Shopclass (Mindstellar).
 * Copyright (c) 2021-2026 Mindstellar Community
 *
 * Distributed under the GNU General Public License v3.0 or later. See LICENSE.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use mindstellar\database\Connection;
use mindstellar\migration\MigrationInterface;

/**
 * Add t_admin_2fa, the per-administrator TOTP enrollment row.
 *
 * Authenticator-app 2FA is optional and is only challenged when the sign-in
 * address differs from the last verified one. The secret lives here encrypted,
 * not on t_admin, so an administrator who never enrolls has no extra column and
 * a deleted administrator takes the row with them (ON DELETE CASCADE).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS.
 */
return new class () implements MigrationInterface {
    public function up(Connection $conn): void
    {
        $table = DB_TABLE_PREFIX . 't_admin_2fa';
        $admin = DB_TABLE_PREFIX . 't_admin';

        $conn->execute(
            'CREATE TABLE IF NOT EXISTS ' . $table . ' ('
            . ' fk_i_admin_id INT UNSIGNED NOT NULL,'
            . ' s_secret VARCHAR(255) NOT NULL DEFAULT \'\','
            . ' b_enabled TINYINT(1) NOT NULL DEFAULT 0,'
            . ' s_last_ip VARCHAR(45) NOT NULL DEFAULT \'\','
            . ' s_backup_codes TEXT NULL,'
            . ' dt_enrolled DATETIME NULL,'
            . ' dt_last_verify DATETIME NULL,'
            . ' PRIMARY KEY (fk_i_admin_id),'
            . ' FOREIGN KEY (fk_i_admin_id) REFERENCES ' . $admin . ' (pk_i_id) ON DELETE CASCADE'
            . ') ENGINE=InnoDB DEFAULT CHARACTER SET \'utf8mb4\' COLLATE \'utf8mb4_general_ci\''
        );
    }
};

/* file end: ./oc-includes/osclass/installer/migrations/0029_admin_2fa.php */
