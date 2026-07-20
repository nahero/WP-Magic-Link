<?php
/**
 * Fires only when the plugin is actually deleted from the Plugins screen
 * (not on deactivation) - removes everything this plugin stored so no
 * orphaned data is left behind. WordPress core includes this file directly
 * and defines WP_UNINSTALL_PLUGIN first; if that's not set, this file was
 * requested directly and must not run.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

delete_option('msv_magic_link_auth_settings');
delete_option('msv_magic_link_auth_log');
delete_option('msv_magic_link_auth_disposable');
delete_transient('msv_magic_link_auth_gh_release');

// Magic-link tokens and per-IP rate-limit counters are stored as transients
// with a dynamic suffix (the token / the IP hash), so there's no fixed
// option name to delete_transient() - a direct query is the only way to
// find and remove all of them.
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
        $wpdb->esc_like('_transient_msv_magic_token_') . '%',
        $wpdb->esc_like('_transient_timeout_msv_magic_token_') . '%',
        $wpdb->esc_like('_transient_msv_magic_rate_') . '%',
        $wpdb->esc_like('_transient_timeout_msv_magic_rate_') . '%'
    )
);
