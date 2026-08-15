<?php if (!defined('OC_ADMIN')) {
    exit('Direct access is not allowed.');
}
/*
 * This file is part of Shopclass (Mindstellar).
 * Copyright (c) 2014 Osclass (original work, licensed under the Apache License 2.0)
 * Copyright (c) 2021-2026 Mindstellar Community
 *
 * Distributed under the GNU General Public License v3.0 or later. The original
 * Osclass code it derives from was licensed under the Apache License 2.0.
 * See LICENSE (GPL-3.0) and LICENSE-APACHE (Apache-2.0).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

$admin = __get('admin');
/**
 * @return array
 */
function customFrmText()
{
    $admin  = __get('admin');
    $return = array();
    if (isset($admin['pk_i_id'])) {
        $return['admin_edit'] = true;
        $return['title']      = __('Edit admin');
        $return['action_frm'] = 'edit_post';
        $return['btn_text']   = __('Save');
    } else {
        $return['admin_edit'] = false;
        $return['title']      = __('Add admin');
        $return['action_frm'] = 'add_post';
        $return['btn_text']   = __('Add');
    }

    return $return;
}

osc_admin_page(array(
    'section' => __('Users'),
));

$aux = customFrmText();

/**
 * @param $string
 *
 * @return string
 */
function customPageTitle($string)
{
    $aux = customFrmText();

    return sprintf('%s &raquo; %s', $aux['title'], $string);
}

osc_add_filter('admin_title', 'customPageTitle');

osc_current_admin_theme_path('parts/header.php'); ?>
    <?php osc_admin_page_head($aux['title']); ?>
    <!-- add/edit admin form -->
    <div class="settings-user">
        <ul id="error_list"></ul>
        <form name="admin_form" action="<?php echo osc_admin_base_url(true); ?>" method="post">
            <input type="hidden" name="action" value="<?php echo $aux['action_frm']; ?>"/>
            <input type="hidden" name="page" value="admins"/>
            <?php AdminForm::primary_input_hidden($admin); ?>
            <?php AdminForm::js_validation(); ?>
            <fieldset>
                <div class="form-horizontal">
                    <div class="form-row">
                        <div class="form-label"><?php _e('Name <em>(required)</em>'); ?></div>
                        <div class="form-controls">
                            <?php AdminForm::name_text($admin); ?>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-label"><?php _e('Username <em>(required)</em>'); ?></div>
                        <div class="form-controls"><?php AdminForm::username_text($admin); ?></div>
                    </div>
                    <div class="form-row">
                        <div class="form-label"><?php _e('E-mail <em>(required)</em>'); ?></div>
                        <div class="form-controls"><?php AdminForm::email_text($admin); ?></div>
                    </div>
                    <?php if (!$aux['admin_edit']
                              || ($aux['admin_edit']
                                  && Params::getParam('id') != osc_logged_admin_id()
                                  && Params::getParam('id') != '')
                    ) { ?>
                        <div class="form-row">
                            <div class="form-label"><?php _e('Admin type <em>(required)</em>'); ?></div>
                            <div class="form-controls">
                                                       <?php AdminForm::type_select($admin); ?>
                                <p class="help-inline">
                                    <em><?php _e('Administrators have total control over all aspects of your installation, '
                                                 . 'while moderators are only allowed to moderate listings, comments and media files');
                        ?></em>
                                </p>
                            </div>
                        </div>
                    <?php } ?>
                    <div class="form-row">
                        <div class="form-label"><?php _e('New password'); ?></div>
                        <div class="form-controls">
                            <?php AdminForm::password_text($admin); ?>
                        </div>
                    </div>
                    <?php if ($aux['admin_edit']) { ?>
                        <div class="form-row">
                            <div class="form-label"><?php _e('Confirm new password'); ?></div>
                            <div class="form-controls">
                                <?php AdminForm::check_password_text($admin); ?>
                                <p class="help-inline"><em><?php _e('Type your new password again'); ?></em></p>
                            </div>
                        </div>
                    <?php } ?>

                    <hr/>
                    <div class="form-row">
                        <div class="form-label"><?php _e('Your current password'); ?></div>
                        <div class="form-controls">
                            <?php AdminForm::old_password_text(); ?>
                            <p class="help-inline">
                                <em><?php _e('For security, type <b>your current password</b>'); ?></em></p>
                        </div>
                    </div>


                    <?php osc_run_hook('admin_profile_form', $admin); ?>
                    <div class="clear"></div>
                    <?php
                    $formActions = array();
                    if ($aux['admin_edit']) {
                        $formActions[] = array('label' => __('Cancel'), 'url' => 'javascript:history.go(-1)', 'variant' => 'dim');
                    }
                    $formActions[] = array('label' => $aux['btn_text'], 'type' => 'submit', 'variant' => 'primary');
                    osc_admin_form_actions($formActions);
                    ?>
                </div>
            </fieldset>
        </form>
    </div>
    <?php if ($aux['admin_edit'] && isset($admin['pk_i_id']) && (int)$admin['pk_i_id'] === (int)osc_logged_admin_id()) {
        $totpOn     = \mindstellar\security\AdminTotp::isEnabled($admin['pk_i_id']);
        $totpEnroll = (string)Session::newInstance()->_get('admin_totp_enroll_secret');
        $totpBackup = (string)Session::newInstance()->_get('admin_totp_backup_once');
        if ($totpBackup !== '') {
            Session::newInstance()->_drop('admin_totp_backup_once');
        }
        $totpRow = \mindstellar\security\AdminTotp::load($admin['pk_i_id']);
        $totpIp  = ($totpRow && !empty($totpRow['s_last_ip'])) ? $totpRow['s_last_ip'] : '';
        ?>
    <div class="settings-user" style="margin-top:2rem;">
        <h2 class="render-title"><?php _e('Two-factor authentication'); ?></h2>
        <p><?php _e('When this is on, a new IP address must confirm a code from your authenticator app. The same IP can sign in with password only.'); ?></p>
        <?php if ($totpBackup !== '') { ?>
            <div class="flashmessage flashmessage-ok" style="display:block;">
                <p><strong><?php _e('Backup codes (save these now)'); ?></strong></p>
                <p style="font-family:monospace;letter-spacing:.08em;"><?php echo osc_esc_html($totpBackup); ?></p>
            </div>
        <?php } ?>
        <?php if ($totpEnroll !== '' && !$totpOn) {
            $totpUri = \mindstellar\security\AdminTotp::otpauthUri($admin['s_username'], $totpEnroll);
            ?>
            <p><?php _e('Add this account in your authenticator app, then enter the 6-digit code to confirm.'); ?></p>
            <p><?php _e('Key:'); ?> <code><?php echo osc_esc_html($totpEnroll); ?></code></p>
            <p><a href="<?php echo osc_esc_html($totpUri); ?>"><?php _e('Open in authenticator'); ?></a></p>
            <form action="<?php echo osc_admin_base_url(true); ?>" method="post">
                <input type="hidden" name="page" value="admins"/>
                <input type="hidden" name="action" value="2fa_confirm"/>
                <div class="form-horizontal">
                    <div class="form-row">
                        <div class="form-label"><?php _e('Authenticator code'); ?></div>
                        <div class="form-controls">
                            <input type="text" name="code" value="" maxlength="6" autocomplete="one-time-code" required/>
                            <button type="submit" class="btn btn-primary"><?php echo osc_esc_html(__('Confirm and enable')); ?></button>
                        </div>
                    </div>
                </div>
            </form>
        <?php } elseif ($totpOn) { ?>
            <p><?php _e('Status: on'); ?><?php if ($totpIp !== '') {
                echo ' — ' . osc_esc_html(sprintf(__('last verified IP: %s'), $totpIp));
            } ?></p>
            <form action="<?php echo osc_admin_base_url(true); ?>" method="post">
                <input type="hidden" name="page" value="admins"/>
                <input type="hidden" name="action" value="2fa_disable"/>
                <div class="form-horizontal">
                    <div class="form-row">
                        <div class="form-label"><?php _e('Code to disable'); ?></div>
                        <div class="form-controls">
                            <input type="text" name="code" value="" maxlength="8" autocomplete="one-time-code" required/>
                            <button type="submit" class="btn"><?php echo osc_esc_html(__('Turn off 2FA')); ?></button>
                        </div>
                    </div>
                </div>
            </form>
        <?php } else { ?>
            <form action="<?php echo osc_admin_base_url(true); ?>" method="post">
                <input type="hidden" name="page" value="admins"/>
                <input type="hidden" name="action" value="2fa_start"/>
                <button type="submit" class="btn btn-primary"><?php echo osc_esc_html(__('Set up authenticator')); ?></button>
            </form>
        <?php } ?>
    </div>
    <?php } ?>
    <!-- /add user form -->
<?php osc_current_admin_theme_path('parts/footer.php'); ?>