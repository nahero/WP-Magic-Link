<?php
/**
 * Plugin Name: WP Magic Link Auth
 * Description: Passwordless magic-link authentication with rate limiting, an optional protected page, Cloudflare Turnstile support, and a disposable-email blocklist. Works via a shortcode or an Elementor Pro form action.
 * Author: igor@igibits.com
 * Version: 0.9.0
 * Requires at least: 6.0
 * Requires PHP: 8.4
 * Text Domain: msv-magic-link-auth
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

final class MSV_Magic_Link_Auth {
    private const OPTION_KEY = 'msv_magic_link_auth_settings';
    private const LOG_OPTION_KEY = 'msv_magic_link_auth_log';
    private const LOG_HARD_CAP = 5000; // safety ceiling only; normal pruning is time-based, see log_event()
    private const TOKEN_PREFIX = 'msv_magic_token_';
    private const RATE_PREFIX = 'msv_magic_rate_';
    private const NONCE_ACTION = 'msv_magic_request';
    private const SETTINGS_NONCE_ACTION = 'msv_magic_settings_save';
    private const CONFIRM_NONCE_ACTION = 'msv_magic_confirm';
    private const SETTINGS_PAGE_SLUG = 'msv-magic-link-auth';
    private const QUERY_VAR = 'msv_magic_token';
    private const GITHUB_OWNER = 'nahero';
    private const GITHUB_REPO = 'WP-Magic-Link';
    private const GITHUB_TOKEN_CONSTANT_NAME = 'MSV_MAGIC_LINK_GITHUB_TOKEN';
    private const UPDATE_RELEASE_CACHE_KEY = 'msv_magic_link_auth_gh_release';
    private const UPDATE_RELEASE_CACHE_TTL = 6 * HOUR_IN_SECONDS;
    private const UPDATE_RELEASE_NEGATIVE_TTL = 5 * MINUTE_IN_SECONDS;
    private const DISPOSABLE_OPTION_KEY = 'msv_magic_link_auth_disposable';
    private const DISPOSABLE_BLOCKLIST_URL = 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf';
    private const TOTALPOLL_SCHEDULE_OPTION_KEY = 'msv_magic_link_auth_totalpoll_schedule';
    private const VOTER_DELETE_SCHEDULE_OPTION_KEY = 'msv_magic_link_auth_voter_delete_schedule';
    private const VOTER_CREATED_META_KEY = '_msv_magic_link_voter';
    private const TOTALPOLL_CRON_HOOK = 'msv_magic_link_totalpoll_purge_cron';
    private const VOTER_DELETE_CRON_HOOK = 'msv_magic_link_voter_delete_cron';

    private static ?self $instance = null;

    public function __construct() {
        self::$instance = $this;

        register_activation_hook(__FILE__, [$this, 'handle_activation']);
        register_deactivation_hook(__FILE__, [$this, 'handle_deactivation']);

        add_action('init', [$this, 'load_textdomain']);
        add_shortcode('msv_magic_link_form', [$this, 'render_form_shortcode']);
        add_action('init', [$this, 'handle_form_submission']);
        add_action('init', [$this, 'handle_magic_link_confirm']);
        add_action('template_redirect', [$this, 'handle_magic_link_landing']);
        add_action('template_redirect', [$this, 'protect_vote_page'], 1);
        add_action('after_setup_theme', [$this, 'hide_admin_bar_for_non_admins']);
        add_action('elementor_pro/forms/actions/register', [$this, 'register_elementor_form_action']);
        add_action('admin_menu', [$this, 'register_settings_page']);
        add_action('wp_body_open', [$this, 'render_status_notice']);
        add_action('wp_footer', [$this, 'render_confirm_button']);
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        add_filter('plugins_api', [$this, 'plugins_api_handler'], 10, 3);
        add_action(self::TOTALPOLL_CRON_HOOK, [$this, 'run_scheduled_totalpoll_purge']);
        add_action(self::VOTER_DELETE_CRON_HOOK, [$this, 'run_scheduled_voter_delete']);
    }

    public static function instance(): self {
        return self::$instance;
    }

    public function load_textdomain(): void {
        load_plugin_textdomain('msv-magic-link-auth', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

    /**
     * Restores any pending scheduled runs from saved config. Runs on every
     * activation (including a deactivate/reactivate cycle weeks later), not
     * just the first install, so cron continuity survives a toggle without
     * requiring the admin to revisit the settings screen.
     */
    public function handle_activation(): void {
        $this->arm_schedule(self::TOTALPOLL_SCHEDULE_OPTION_KEY, self::TOTALPOLL_CRON_HOOK);
        $this->arm_schedule(self::VOTER_DELETE_SCHEDULE_OPTION_KEY, self::VOTER_DELETE_CRON_HOOK);
    }

    public function handle_deactivation(): void {
        wp_clear_scheduled_hook(self::TOTALPOLL_CRON_HOOK);
        wp_clear_scheduled_hook(self::VOTER_DELETE_CRON_HOOK);
    }

    public static function defaults(): array {
        return [
            'site_key' => '',
            'secret_key' => '',
            'request_page_path' => '',
            'confirm_page_path' => '',
            'vote_page_path' => '',
            'future_request_page_path' => '/',
            'token_ttl' => DAY_IN_SECONDS,
            'max_attempts_per_hour' => 3,
            'email_from_name' => get_bloginfo('name'),
            'email_subject' => __('Your magic link', 'msv-magic-link-auth'),
            'dev_mode' => false,
            'dev_mode_minutes' => 10,
            'turnstile_enabled' => false,
            'msg_sent' => __('Check your email: we just sent you your magic link.', 'msv-magic-link-auth'),
            'msg_invalid' => __('This link is no longer valid. It may have already been used or expired. Please request a new one below.', 'msv-magic-link-auth'),
            'msg_rate_limited' => __('Too many attempts from this address. Please try again later.', 'msv-magic-link-auth'),
            'msg_captcha_failed' => __('Security verification failed. Please try again.', 'msv-magic-link-auth'),
            'msg_email_required' => __('Please enter a valid email address.', 'msv-magic-link-auth'),
            'msg_confirm' => __('Click the button below to confirm your identity and continue.', 'msv-magic-link-auth'),
            'msg_disposable' => __('Disposable email addresses are not allowed. Please use a personal address.', 'msv-magic-link-auth'),
            'custom_disposable_domains' => '',
            'disposable_allowlist' => '',
            'log_retention_days' => 3,
            'totalpoll_table_suffix' => 'totalpoll_log',
            'totalpoll_ip_column' => 'ip',
            'voter_delete_match_mode' => 'role',
        ];
    }

    public static function settings(): array {
        $settings = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());

        if (!empty($settings['dev_mode'])) {
            $settings['token_ttl'] = max(1, (int) $settings['dev_mode_minutes']) * MINUTE_IN_SECONDS;
        }

        $settings['request_page_path'] = self::resolve_stored_page_path((string) $settings['request_page_path'], '/');
        $settings['vote_page_path'] = self::resolve_stored_page_path((string) $settings['vote_page_path'], '/');
        $settings['confirm_page_path'] = self::resolve_stored_page_path((string) $settings['confirm_page_path'], '');

        return $settings;
    }

    /**
     * Resolves a stored path/page-ID setting to an actual relative URL path.
     * A digit-only stored value is a WordPress page ID (the normal case once
     * the settings page's page picker has been used); anything else is a
     * legacy free-text path or the explicit "Custom / other" fallback value,
     * used as-is. Falls back to $empty_fallback if empty, or if a stored
     * page ID no longer resolves (page deleted/unpublished since it was
     * picked).
     */
    private static function resolve_stored_page_path(string $stored, string $empty_fallback): string {
        if ($stored === '') {
            return $empty_fallback;
        }

        if (ctype_digit($stored)) {
            $permalink = get_permalink((int) $stored);
            if (!$permalink) {
                return $empty_fallback;
            }
            $path = (string) wp_parse_url($permalink, PHP_URL_PATH);
            return $path === '' ? $empty_fallback : untrailingslashit('/' . ltrim($path, '/'));
        }

        return $stored;
    }

    private function log_event(string $level, string $message): void {
        $log = get_option(self::LOG_OPTION_KEY, []);
        if (!is_array($log)) {
            $log = [];
        }

        array_unshift($log, [
            'time' => current_time('mysql'), // display only, respects site timezone
            'ts' => time(),                  // unambiguous UTC epoch, used for retention below
            'level' => $level,
            'message' => $message,
        ]);

        // Pruned by age (log_retention_days), not just count - during a busy
        // voting day a fixed entry-count cap could get consumed in an hour
        // and silently drop same-day history. Entries from before this field
        // existed have no 'ts' and are treated as already-expired (pruned on
        // the next write, self-migrating). LOG_HARD_CAP is just a safety
        // ceiling in case of runaway logging, not the normal eviction path.
        $retention_days = max(1, (int) self::settings()['log_retention_days']);
        $cutoff = time() - ($retention_days * DAY_IN_SECONDS);
        $log = array_values(array_filter($log, static function ($entry) use ($cutoff) {
            return (int) ($entry['ts'] ?? 0) >= $cutoff;
        }));

        update_option(self::LOG_OPTION_KEY, array_slice($log, 0, self::LOG_HARD_CAP), false);
    }

    private static function schedule_defaults(): array {
        return [
            'mode' => 'off', // 'off' | 'once' | 'repeating'
            'once_at' => '',
            'repeat_start_at' => '',
            'repeat_interval_days' => 7,
            'repeat_end_at' => '',
            'next_run_ts' => null,
            'last_run_ts' => null,
            'last_run_status' => '',
            'last_run_message' => '',
        ];
    }

    private function get_schedule(string $option_key): array {
        return wp_parse_args(get_option($option_key, []), self::schedule_defaults());
    }

    /**
     * Parses a datetime-local input value ("Y-m-d\TH:i") as literal
     * site-local wall-clock time (never the browser's own timezone).
     * Returns null if unparseable/blank.
     */
    private function parse_site_local_datetime_object(string $raw): ?DateTime {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }

        try {
            return new DateTime(str_replace('T', ' ', $raw), wp_timezone());
        } catch (Exception $e) {
            return null;
        }
    }

    private function parse_site_local_datetime(string $raw): ?int {
        $date = $this->parse_site_local_datetime_object($raw);
        return $date instanceof DateTime ? $date->getTimestamp() : null;
    }

    /**
     * Finds the first occurrence of a "every N days, starting at
     * $start_at_local, no later than $end_at_local" schedule that falls
     * strictly after $after_ts. Walks whole calendar days via DateInterval
     * on a timezone-aware DateTime (not raw N*86400 arithmetic) so a
     * DST transition can't shift the wall-clock time of day or cause drift.
     * Returns null once the window has elapsed - the caller treats that as
     * "nothing left to schedule", not an error.
     */
    private function compute_next_occurrence_ts(string $start_at_local, int $interval_days, string $end_at_local, int $after_ts): ?int {
        $interval_days = max(1, $interval_days);

        $cursor = $this->parse_site_local_datetime_object($start_at_local);
        $end_ts = $this->parse_site_local_datetime($end_at_local);
        if ($cursor === null || $end_ts === null) {
            return null;
        }
        $start_ts = $cursor->getTimestamp();
        if ($end_ts < $start_ts) {
            return null;
        }

        if ($start_ts > $after_ts) {
            $next_ts = $start_ts;
        } else {
            // $steps counts whole INTERVALS elapsed since start, so the walk
            // must advance $steps * $interval_days days, not $steps days.
            $steps = (int) ceil(($after_ts - $start_ts) / ($interval_days * DAY_IN_SECONDS));
            $cursor->add(new DateInterval('P' . ($steps * $interval_days) . 'D'));
            $next_ts = $cursor->getTimestamp();
            if ($next_ts <= $after_ts) {
                $cursor->add(new DateInterval('P' . $interval_days . 'D'));
                $next_ts = $cursor->getTimestamp();
            }
        }

        return $next_ts <= $end_ts ? $next_ts : null;
    }

    /**
     * Re-derives and (re)schedules the single next WP-Cron event for a
     * schedule option, always clearing any stale pending event first so
     * re-arming is idempotent and safe to call after every save and on
     * every plugin activation. A lapsed 'once' schedule (its time already
     * passed) is intentionally left unscheduled rather than fired
     * immediately - critical so reactivating the plugin long after a
     * forgotten one-time schedule can't suddenly trigger a destructive
     * action moments after reactivation.
     */
    private function arm_schedule(string $option_key, string $cron_hook): void {
        $schedule = $this->get_schedule($option_key);
        wp_clear_scheduled_hook($cron_hook);

        $next_run_ts = null;

        if ($schedule['mode'] === 'once') {
            $ts = $this->parse_site_local_datetime($schedule['once_at']);
            if ($ts !== null && $ts > time()) {
                wp_schedule_single_event($ts, $cron_hook);
                $next_run_ts = $ts;
            }
        } elseif ($schedule['mode'] === 'repeating') {
            $ts = $this->compute_next_occurrence_ts(
                $schedule['repeat_start_at'],
                (int) $schedule['repeat_interval_days'],
                $schedule['repeat_end_at'],
                time()
            );
            if ($ts !== null) {
                wp_schedule_single_event($ts, $cron_hook);
                $next_run_ts = $ts;
            }
        }

        $schedule['next_run_ts'] = $next_run_ts;
        update_option($option_key, $schedule, false);
    }

    public function render_form_shortcode(): string {
        $settings = self::settings();
        $message = '';
        $error = '';

        if (isset($_GET['msv_magic_status'])) {
            // Reuses the same editable messages as render_status_notice() (the
            // Elementor-path toast) rather than a separate hardcoded set, so
            // editing a message once in Messaging applies everywhere it's shown.
            $status = sanitize_key(wp_unslash($_GET['msv_magic_status']));
            if ($status === 'sent') {
                $message = $settings['msg_sent'];
            } elseif ($status === 'invalid') {
                $error = $settings['msg_invalid'];
            } elseif ($status === 'rate_limited') {
                $error = $settings['msg_rate_limited'];
            } elseif ($status === 'captcha_failed') {
                $error = $settings['msg_captcha_failed'];
            } elseif ($status === 'email_required') {
                $error = $settings['msg_email_required'];
            } elseif ($status === 'disposable') {
                $error = $settings['msg_disposable'];
            }
        }

        ob_start();
        ?>
        <div class="msv-magic-link-wrap">
            <?php if ($message): ?>
                <div class="msv-magic-link-message msv-magic-link-success"><?php echo esc_html($message); ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="msv-magic-link-message msv-magic-link-error"><?php echo esc_html($error); ?></div>
            <?php endif; ?>
            <form method="post" class="msv-magic-link-form" action="<?php echo esc_url($this->current_request_page_url()); ?>">
                <input type="hidden" name="msv_magic_link_action" value="request_link">
                <?php wp_nonce_field(self::NONCE_ACTION, 'msv_magic_nonce'); ?>
                <p>
                    <label for="msv_magiclinkemail" class="screen-reader-text"><?php esc_html_e('Email', 'msv-magic-link-auth'); ?></label>
                    <input type="email" id="msv_magiclinkemail" name="magiclinkemail" required autocomplete="email" placeholder="<?php esc_attr_e('Email', 'msv-magic-link-auth'); ?>" />
                </p>
                <?php if (!empty($settings['turnstile_enabled'])): ?>
                    <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($settings['site_key']); ?>" data-theme="auto"></div>
                <?php endif; ?>
                <p>
                    <button type="submit"><?php esc_html_e('Send magic link', 'msv-magic-link-auth'); ?></button>
                </p>
            </form>
        </div>
        <?php if (!empty($settings['turnstile_enabled'])): ?>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <?php endif; ?>
        <?php
        return (string) ob_get_clean();
    }

    public function handle_form_submission(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        $action = isset($_POST['msv_magic_link_action']) ? sanitize_text_field(wp_unslash($_POST['msv_magic_link_action'])) : '';
        if ($action !== 'request_link') {
            return;
        }

        if (!isset($_POST['msv_magic_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['msv_magic_nonce'])), self::NONCE_ACTION)) {
            wp_die(esc_html__('Invalid request.', 'msv-magic-link-auth'), 403);
        }

        $redirect_url = $this->current_request_page_url();
        $email = isset($_POST['magiclinkemail']) ? sanitize_email(wp_unslash($_POST['magiclinkemail'])) : '';
        if (!$email || !is_email($email)) {
            wp_safe_redirect(add_query_arg('msv_magic_status', 'email_required', $redirect_url));
            exit;
        }
        $email = $this->normalize_email($email);

        if ($this->is_disposable_email($email)) {
            $this->log_event('warning', 'Blocked disposable email domain: ' . substr($email, strrpos($email, '@') + 1));
            wp_safe_redirect(add_query_arg('msv_magic_status', 'disposable', $redirect_url));
            exit;
        }

        if ($this->is_rate_limited()) {
            wp_safe_redirect(add_query_arg('msv_magic_status', 'rate_limited', $redirect_url));
            exit;
        }

        if (!empty(self::settings()['turnstile_enabled'])) {
            $turnstile_response = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';
            if (!$this->verify_turnstile($turnstile_response)) {
                $this->increment_rate_limit();
                wp_safe_redirect(add_query_arg('msv_magic_status', 'captcha_failed', $redirect_url));
                exit;
            }
        }

        $this->increment_rate_limit();

        $result = $this->issue_magic_link($email);
        if (is_wp_error($result)) {
            wp_die(esc_html($result->get_error_message()), 500);
        }

        wp_safe_redirect(add_query_arg('msv_magic_status', 'sent', $redirect_url));
        exit;
    }

    /**
     * Handles submissions coming from an Elementor Pro form via the
     * "Magic Link Auth" action registered in register_elementor_form_action().
     * Elementor's own AJAX handler never reaches handle_form_submission()
     * above (different POST shape/route), so this is a separate entry point
     * into the same rate-limit/turnstile/issue_magic_link logic.
     *
     * @param \ElementorPro\Modules\Forms\Classes\Form_Record $record
     * @param \ElementorPro\Modules\Forms\Classes\Ajax_Handler $ajax_handler
     */
    public function handle_elementor_form_submission($record, $ajax_handler): void {
        $settings = self::settings();
        $fields = $record->get('fields');
        $email = isset($fields['magiclinkemail']['value']) ? sanitize_email($fields['magiclinkemail']['value']) : '';

        if (!$email || !is_email($email)) {
            $ajax_handler->add_error_message($settings['msg_email_required']);
            return;
        }
        $email = $this->normalize_email($email);

        if ($this->is_disposable_email($email)) {
            $this->log_event('warning', 'Blocked disposable email domain: ' . substr($email, strrpos($email, '@') + 1));
            $ajax_handler->add_error_message($settings['msg_disposable']);
            return;
        }

        if ($this->is_rate_limited()) {
            $ajax_handler->add_error_message($settings['msg_rate_limited']);
            return;
        }

        // Turnstile is intentionally NOT re-verified here: the "Simple Cloudflare
        // Turnstile" plugin is configured to validate it as part of Elementor's
        // own form validation, which already ran (and consumed the token) before
        // this action fires. A second siteverify call on the same token always
        // fails with "timeout-or-duplicate" since Turnstile tokens are single-use.
        $this->increment_rate_limit();

        $result = $this->issue_magic_link($email);
        if (is_wp_error($result)) {
            $ajax_handler->add_error_message($result->get_error_message());
        }
    }

    /**
     * Registers the "Magic Link Auth" action so it can be attached under an
     * Elementor Pro form's "Actions After Submit". Delegates the actual
     * class declaration to msv_magic_link_declare_elementor_action() below:
     * PHP does not allow a class to be declared inside a class method, only
     * inside a plain function, and it must stay lazy because Action_Base
     * only exists once Elementor Pro has loaded (after this MU-plugin file
     * is parsed).
     */
    public function register_elementor_form_action($form_actions_registrar): void {
        $base_class = '\ElementorPro\Modules\Forms\Classes\Action_Base';
        if (!class_exists($base_class)) {
            return;
        }

        // A "class must implement remaining abstract methods" error happens at
        // class-declaration time and is NOT catchable with try/catch, so we
        // check the contract via Reflection before ever declaring our subclass
        // instead of declaring it and hoping it matches.
        $implemented = ['get_name', 'get_label', 'run', 'register_fields', 'register_settings_section', 'on_export'];
        foreach ((new \ReflectionClass($base_class))->getMethods(\ReflectionMethod::IS_ABSTRACT) as $method) {
            if (!in_array($method->getName(), $implemented, true)) {
                $missing = $method->getName();
                $this->log_event('error', 'Skipped Elementor form action registration: ' . $base_class . ' requires ' . $missing . '(), which this plugin does not implement.');
                add_action('admin_notices', function () use ($missing, $base_class) {
                    if (!current_user_can('manage_options')) {
                        return;
                    }
                    printf(
                        '<div class="notice notice-error"><p>%s <a href="%s">%s</a></p></div>',
                        esc_html(sprintf(
                            /* translators: 1: Elementor Pro base class name, 2: missing method name */
                            __('WP Magic Link Auth: the Elementor form action was NOT registered. %1$s requires a method this plugin does not implement: %2$s().', 'msv-magic-link-auth'),
                            $base_class,
                            $missing
                        )),
                        esc_url(admin_url('options-general.php?page=' . self::SETTINGS_PAGE_SLUG)),
                        esc_html__('View log', 'msv-magic-link-auth')
                    );
                });
                return;
            }
        }

        msv_magic_link_declare_elementor_action();
        $form_actions_registrar->register(new MSV_Magic_Link_Elementor_Form_Action());
    }

    /**
     * Creates (or reuses) the WordPress subscriber account for $email,
     * issues a single-use magic-link token, and emails it. Reused by both
     * the shortcode form and the Elementor form action.
     *
     * @return true|WP_Error
     */
    public function issue_magic_link(string $email) {
        $email = $this->normalize_email($email);
        $user = get_user_by('email', $email);
        if (!$user) {
            $username = $this->generate_unique_username_from_email($email);
            $password = wp_generate_password(24, true, true);
            $user_id = wp_create_user($username, $password, $email);
            if (is_wp_error($user_id)) {
                $this->log_event('error', 'wp_create_user failed for ' . $email . ': ' . $user_id->get_error_message());
                return $user_id;
            }
            $user = get_user_by('id', $user_id);
            if ($user instanceof WP_User) {
                $user->set_role('subscriber');
                // Tags accounts this plugin creates, going forward only (not
                // retroactive), so the "delete all voters" maintenance action
                // can optionally target exactly these accounts instead of
                // every Subscriber-role user on the site - see get_voter_user_ids_by_tag().
                update_user_meta($user->ID, self::VOTER_CREATED_META_KEY, time());
            }
        }

        if (!$user instanceof WP_User) {
            return new WP_Error('msv_magic_link_user', 'Unable to create or load user.');
        }

        $token = wp_generate_password(48, false, false);
        $payload = [
            'user_id' => (int) $user->ID,
            'email' => $user->user_email,
            'created' => time(),
        ];
        set_transient(self::TOKEN_PREFIX . $token, $payload, (int) self::settings()['token_ttl']);
        $this->log_event('info', 'Magic link issued for ' . $email . ' (token ' . $this->token_fingerprint($token) . ').');

        $settings = self::settings();
        $landing_path = $settings['confirm_page_path'] !== '' ? $settings['confirm_page_path'] : $settings['request_page_path'];
        $magic_url = add_query_arg(self::QUERY_VAR, rawurlencode($token), home_url($landing_path));
        $this->send_magic_email($user, $magic_url);

        return true;
    }

    /**
     * Handles the GET request from the emailed magic link. This must NEVER
     * consume the token or log anyone in - corporate email security gateways
     * (Microsoft Safe Links, Proofpoint, Mimecast, etc.) fetch every link in
     * an inbound email before the recipient ever sees it, and HTTP GET is
     * supposed to be side-effect-free, so anything relying on GET alone WILL
     * get silently consumed by those scanners before the real voter clicks.
     * This only peeks at validity (redirecting away if already dead) and
     * otherwise lets the page render normally; render_confirm_button() then
     * injects a real confirm button whose form POST (handle_magic_link_confirm()
     * below) is the only thing that actually consumes the token - something
     * scanners don't do, since they don't execute JS or submit forms.
     */
    public function handle_magic_link_landing(): void {
        if (!isset($_GET[self::QUERY_VAR])) {
            return;
        }

        $token = sanitize_text_field(wp_unslash($_GET[self::QUERY_VAR]));
        $payload = get_transient(self::TOKEN_PREFIX . $token);

        if (!is_array($payload) || empty($payload['user_id'])) {
            $this->log_event('warning', 'Magic link landing failed (invalid/expired/already used) - token ' . $this->token_fingerprint($token) . ', requester ' . $this->get_client_ip() . ' / ' . $this->get_user_agent() . '.');
            wp_safe_redirect(add_query_arg('msv_magic_status', 'invalid', $this->current_request_page_url()));
            exit;
        }
    }

    /**
     * Handles the confirm button's form POST - the only place a magic-link
     * token is actually consumed and a session established. See
     * handle_magic_link_landing() above for why this is split from the GET.
     */
    public function handle_magic_link_confirm(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['msv_magic_confirm_token'])) {
            return;
        }

        if (!isset($_POST['msv_magic_confirm_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['msv_magic_confirm_nonce'])), self::CONFIRM_NONCE_ACTION)) {
            wp_die(esc_html__('Invalid request.', 'msv-magic-link-auth'), 403);
        }

        $token = sanitize_text_field(wp_unslash($_POST['msv_magic_confirm_token']));
        $payload = get_transient(self::TOKEN_PREFIX . $token);
        $request_page = $this->current_request_page_url();
        $fingerprint = $this->token_fingerprint($token);
        $requester = $this->get_client_ip() . ' / ' . $this->get_user_agent();

        if (!is_array($payload) || empty($payload['user_id'])) {
            $this->log_event('warning', 'Magic link confirm failed (invalid/expired/already used) - token ' . $fingerprint . ', requester ' . $requester . '.');
            wp_safe_redirect(add_query_arg('msv_magic_status', 'invalid', $request_page));
            exit;
        }

        delete_transient(self::TOKEN_PREFIX . $token);
        $this->log_event('info', 'Magic link confirmed - token ' . $fingerprint . ', email ' . ($payload['email'] ?? '?') . ', requester ' . $requester . '.');

        $user = get_user_by('id', (int) $payload['user_id']);
        if (!$user instanceof WP_User) {
            wp_safe_redirect(add_query_arg('msv_magic_status', 'invalid', $request_page));
            exit;
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true, is_ssl());

        wp_safe_redirect(home_url(self::settings()['vote_page_path']));
        exit;
    }

    public function protect_vote_page(): void {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        $settings = self::settings();
        $vote_path = untrailingslashit($settings['vote_page_path']);

        if ($this->current_uri_path() === $vote_path && !is_user_logged_in()) {
            wp_safe_redirect(home_url($settings['request_page_path']));
            exit;
        }
    }

    /**
     * Prints a floating, dismissible toast for msv_magic_status query-arg
     * outcomes (link sent / invalid / rate-limited / etc.) directly on the
     * request page, independently of the [msv_magic_link_form] shortcode -
     * needed because the real site uses a native Elementor form there, which
     * never renders that shortcode's own message markup. Message text is
     * editable on the settings page (see the "Messages" section).
     */
    public function render_status_notice(): void {
        if (is_admin() || !isset($_GET['msv_magic_status'])) {
            return;
        }

        $settings = self::settings();
        $request_path = untrailingslashit($settings['request_page_path']);

        if ($this->current_uri_path() !== $request_path) {
            return;
        }

        $status = sanitize_key(wp_unslash($_GET['msv_magic_status']));
        $messages = [
            'sent' => ['type' => 'success', 'text' => $settings['msg_sent']],
            'invalid' => ['type' => 'error', 'text' => $settings['msg_invalid']],
            'rate_limited' => ['type' => 'error', 'text' => $settings['msg_rate_limited']],
            'captcha_failed' => ['type' => 'error', 'text' => $settings['msg_captcha_failed']],
            'email_required' => ['type' => 'error', 'text' => $settings['msg_email_required']],
            'disposable' => ['type' => 'error', 'text' => $settings['msg_disposable']],
        ];

        if (!isset($messages[$status]) || $messages[$status]['text'] === '') {
            return;
        }
        ?>
        <div id="msv-magic-link-toast" class="msv-magic-link-toast msv-magic-link-message msv-magic-link-<?php echo esc_attr($messages[$status]['type']); ?>" role="alert">
            <button type="button" class="msv-magic-link-toast-close" aria-label="<?php echo esc_attr__('Dismiss', 'msv-magic-link-auth'); ?>" onclick="document.getElementById('msv-magic-link-toast').remove();">&times;</button>
            <p class="msv-magic-link-toast-text"><?php echo esc_html($messages[$status]['text']); ?></p>
        </div>
        <style>
            .msv-magic-link-toast {
                position: fixed;
                right: 24px;
                bottom: 24px;
                z-index: 99999;
                max-width: 420px;
                padding: 20px 44px 20px 20px;
                border-radius: 10px;
                box-shadow: 0 6px 24px rgba(0, 0, 0, 0.2);
                font-size: 16px;
                line-height: 1.5;
            }
            .msv-magic-link-toast.msv-magic-link-success { background: #e6f4ea; color: #1e4620; }
            .msv-magic-link-toast.msv-magic-link-error { background: #fce8e6; color: #611a15; }
            .msv-magic-link-toast-text { margin: 0; }
            .msv-magic-link-toast-close {
                position: absolute;
                top: 8px;
                right: 10px;
                background: none;
                border: none;
                font-size: 22px;
                line-height: 1;
                cursor: pointer;
                color: inherit;
                opacity: 0.6;
            }
            .msv-magic-link-toast-close:hover { opacity: 1; }
            @media (max-width: 480px) {
                .msv-magic-link-toast { left: 16px; right: 16px; bottom: 16px; max-width: none; }
            }
        </style>
        <?php
    }

    /**
     * Injects the actual confirm button via client-side JS rather than
     * server-rendered HTML, strictly into #confirmation-container on the
     * configured confirm/landing page - never anywhere else, and never
     * falls back to dumping content elsewhere if that container isn't
     * found (logs a warning instead). Hooked on wp_footer, not
     * wp_body_open: the container needs to already exist in the DOM by
     * the time this runs, and wp_body_open fires before Elementor has
     * rendered any page content at all.
     *
     * Client-side injection (vs. server-rendered HTML) is deliberate: the
     * raw GET response contains no state-changing form at all, so an email
     * security scanner that only fetches-and-parses HTML (never executing
     * JS) sees nothing to submit. Only a real browser running this script,
     * and a real human clicking the resulting button, ever produces the
     * POST that handle_magic_link_confirm() acts on.
     */
    public function render_confirm_button(): void {
        if (is_admin() || !isset($_GET[self::QUERY_VAR])) {
            return;
        }

        $settings = self::settings();
        $landing_path = $settings['confirm_page_path'] !== '' ? $settings['confirm_page_path'] : $settings['request_page_path'];

        if ($this->current_uri_path() !== untrailingslashit($landing_path)) {
            return;
        }

        $token = sanitize_text_field(wp_unslash($_GET[self::QUERY_VAR]));
        $payload = get_transient(self::TOKEN_PREFIX . $token); // peek only, never delete here

        if (!is_array($payload) || empty($payload['user_id'])) {
            return; // handle_magic_link_landing() already redirected this case away
        }

        $nonce = wp_create_nonce(self::CONFIRM_NONCE_ACTION);
        $message = $settings['msg_confirm'];
        ?>
        <script>
        (function () {
            var container = document.getElementById('confirmation-container');
            if (!container) {
                if (window.console) {
                    console.warn('WP Magic Link Auth: #confirmation-container not found on this page - confirm button not shown.');
                }
                return;
            }

            var wrap = document.createElement('div');
            wrap.className = 'msv-magic-link-confirm';

            var text = document.createElement('p');
            text.className = 'msv-magic-link-confirm-text';
            text.textContent = <?php echo wp_json_encode($message); ?>;

            var form = document.createElement('form');
            form.method = 'post';

            var tokenField = document.createElement('input');
            tokenField.type = 'hidden';
            tokenField.name = 'msv_magic_confirm_token';
            tokenField.value = <?php echo wp_json_encode($token); ?>;

            var nonceField = document.createElement('input');
            nonceField.type = 'hidden';
            nonceField.name = 'msv_magic_confirm_nonce';
            nonceField.value = <?php echo wp_json_encode($nonce); ?>;

            var button = document.createElement('button');
            button.type = 'submit';
            button.className = 'msv-magic-link-confirm-button';
            button.textContent = <?php echo wp_json_encode(__('Continue', 'msv-magic-link-auth')); ?>;

            form.appendChild(tokenField);
            form.appendChild(nonceField);
            form.appendChild(button);
            wrap.appendChild(text);
            wrap.appendChild(form);
            container.appendChild(wrap);
        })();
        </script>
        <style>
            .msv-magic-link-confirm { text-align: center; padding: 24px; }
            .msv-magic-link-confirm-text { color: #A1A4A5; font-size: 16px; line-height: 1.6; margin: 0 0 20px; }
            .msv-magic-link-confirm-button {
                display: inline-block;
                background: #D4A95E;
                color: #080E10;
                border: none;
                padding: 16px 34px;
                border-radius: 999px;
                font-size: 16px;
                font-weight: 700;
                cursor: pointer;
                font-family: Arial, Helvetica, sans-serif;
            }
        </style>
        <?php
    }

    public function hide_admin_bar_for_non_admins(): void {
        if (!current_user_can('administrator') && !is_admin()) {
            show_admin_bar(false);
        }
    }

    private function current_request_page_url(): string {
        return home_url(self::settings()['request_page_path']);
    }

    private function current_uri_path(): string {
        return untrailingslashit((string) wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH));
    }

    public function verify_turnstile(string $response_token): bool {
        if ($response_token === '') {
            $this->log_event('warning', 'Turnstile verification skipped: no cf-turnstile-response in the submitted request.');
            return false;
        }

        $secret = self::settings()['secret_key'];
        if ($secret === '') {
            $this->log_event('warning', 'Turnstile verification skipped: no secret key configured.');
            return false;
        }

        $remote_ip = $this->get_client_ip();
        $request = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
            'timeout' => 15,
            'body' => [
                'secret' => $secret,
                'response' => $response_token,
                'remoteip' => $remote_ip,
            ],
        ]);

        if (is_wp_error($request)) {
            $this->log_event('error', 'Turnstile siteverify request failed: ' . $request->get_error_message());
            return false;
        }

        $code = wp_remote_retrieve_response_code($request);
        $body = json_decode(wp_remote_retrieve_body($request), true);
        $success = $code === 200 && is_array($body) && !empty($body['success']);

        if (!$success) {
            $error_codes = is_array($body) && !empty($body['error-codes']) ? implode(', ', (array) $body['error-codes']) : 'none returned';
            $this->log_event('warning', 'Turnstile verification failed (HTTP ' . $code . ', error-codes: ' . $error_codes . ').');
        }

        return $success;
    }

    private function get_client_ip(): string {
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
        foreach ($keys as $key) {
            if (empty($_SERVER[$key])) {
                continue;
            }
            $raw = wp_unslash($_SERVER[$key]);
            $ip = trim(explode(',', $raw)[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        return '';
    }

    /**
     * Short, non-reversible identifier for a magic-link token, safe to put in
     * the log (unlike the raw token, which would let anyone reading the log
     * use it to log in as that voter). Lets an "issued" log line and its
     * later "consumed"/"consumption failed" line be matched up by eye.
     */
    private function token_fingerprint(string $token): string {
        return substr(hash('sha256', $token), 0, 10);
    }

    private function get_user_agent(): string {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        return $ua === '' ? '(none)' : substr($ua, 0, 150);
    }

    public function is_rate_limited(): bool {
        $ip = $this->get_client_ip();
        if ($ip === '') {
            return false;
        }

        $count = (int) get_transient(self::RATE_PREFIX . md5($ip));
        return $count >= (int) self::settings()['max_attempts_per_hour'];
    }

    public function increment_rate_limit(): void {
        $ip = $this->get_client_ip();
        if ($ip === '') {
            return;
        }

        $key = self::RATE_PREFIX . md5($ip);
        $count = (int) get_transient($key);
        set_transient($key, $count + 1, HOUR_IN_SECONDS);
    }

    /**
     * Collapses address variants to one canonical account: strips a
     * "+suffix" from the local part for any domain (subaddressing - the
     * base address is always the real deliverable inbox), and additionally
     * strips dots from the local part for Gmail/Googlemail specifically
     * (Gmail ignores dots; other providers treat them as significant, so
     * this is NOT applied generally). Defeats the voter+1@gmail.com /
     * voter+2@gmail.com / v.o.t.e.r@gmail.com multi-account trick.
     */
    private function normalize_email(string $email): string {
        $email = strtolower(trim($email));
        $at = strrpos($email, '@');
        if ($at === false) {
            return $email;
        }

        $local = substr($email, 0, $at);
        $domain = substr($email, $at + 1);

        $plus = strpos($local, '+');
        if ($plus !== false) {
            $local = substr($local, 0, $plus);
        }

        if ($domain === 'gmail.com' || $domain === 'googlemail.com') {
            $local = str_replace('.', '', $local);
        }

        return $local . '@' . $domain;
    }

    /**
     * Builds the effective disposable-domain lookup set: the refreshed
     * list (see refresh_disposable_list_from_source()) if one has ever
     * been fetched, else the bundled snapshot shipped with the plugin -
     * minus the admin's own allowlist, plus the admin's own custom
     * blocklist. Returns a domain => true map for O(1) isset() lookups.
     * Static-cached per request since this can be checked multiple times
     * (e.g. shortcode + Elementor paths are mutually exclusive per
     * request, but issue_magic_link() may also be called directly).
     */
    private function get_disposable_domains(): array {
        static $domains = null;
        if ($domains !== null) {
            return $domains;
        }

        $refreshed = get_option(self::DISPOSABLE_OPTION_KEY, []);
        if (is_array($refreshed) && !empty($refreshed['domains'])) {
            $list = $refreshed['domains'];
        } else {
            $bundled = @file_get_contents(__DIR__ . '/assets/disposable-domains.txt');
            $list = $bundled !== false ? preg_split('/\r\n|\r|\n/', $bundled) : [];
        }

        $settings = self::settings();
        $custom = $this->parse_domain_list($settings['custom_disposable_domains']);
        $allow = $this->parse_domain_list($settings['disposable_allowlist']);

        $domains = array_fill_keys(array_diff(array_merge((array) $list, $custom), $allow), true);

        return $domains;
    }

    /**
     * Splits a textarea's newline-separated domains into a clean lowercase
     * array, dropping blanks and #-comments. Shared by the custom-blocklist
     * and allowlist settings fields.
     */
    private function parse_domain_list(string $raw): array {
        $lines = preg_split('/\r\n|\r|\n/', $raw);
        $domains = [];
        foreach ($lines as $line) {
            $line = strtolower(trim($line));
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $domains[] = $line;
        }
        return $domains;
    }

    /**
     * Fails open: an empty/unavailable list means every email is allowed.
     * Never block a legitimate voter because a list failed to load.
     */
    private function is_disposable_email(string $email): bool {
        $at = strrpos($email, '@');
        if ($at === false) {
            return false;
        }

        $domains = $this->get_disposable_domains();
        if (empty($domains)) {
            return false;
        }

        $labels = explode('.', strtolower(substr($email, $at + 1)));
        while (count($labels) >= 2) {
            if (isset($domains[implode('.', $labels)])) {
                return true;
            }
            array_shift($labels);
        }

        return false;
    }

    private function generate_unique_username_from_email(string $email): string {
        $base = sanitize_user(current(explode('@', $email)), true);
        if ($base === '') {
            $base = 'voter';
        }

        $username = $base;
        $i = 1;
        while (username_exists($username)) {
            $username = $base . $i;
            $i++;
        }

        return $username;
    }

    private function send_magic_email(WP_User $user, string $magic_url): void {
        $settings = self::settings();
        $subject = $settings['email_subject'];
        $html_lang = esc_attr(get_bloginfo('language'));

        // Only reference a bundled logo if one actually exists - a fresh
        // install of this plugin elsewhere won't have a site-specific logo
        // file, and a missing image is better than a broken <img> in every email.
        $logo_html = '';
        if (file_exists(__DIR__ . '/assets/logo.png')) {
            $logo_url = plugins_url('assets/logo.png', __FILE__);
            $logo_html = '<tr><td align="left" style="padding:0 0 28px;"><img src="' . esc_url($logo_url) . '" alt="' . esc_attr(get_bloginfo('name')) . '" width="200" style="display:block;width:200px;height:auto;"></td></tr>';
        }

        $intro = __('Click the button below to continue. This link is valid for a limited time and can only be used once.', 'msv-magic-link-auth');
        $button_label = __('Continue', 'msv-magic-link-auth');
        $fallback_label = __('If the button doesn\'t work, use this link:', 'msv-magic-link-auth');
        $footer = __('If you did not request this link, you can safely ignore this email.', 'msv-magic-link-auth');

        $message = '<!DOCTYPE html><html lang="' . $html_lang . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>' . esc_html($subject) . '</title></head>'
            . '<body style="margin:0;padding:0;background-color:#080e10;font-family:Arial,Helvetica,sans-serif;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#080e10;margin:0;padding:0;"><tr><td align="center" style="padding:48px 20px;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;">'
            . $logo_html
            . '<tr><td style="background-color:#2e3335;border:4px solid #d4a95e;border-radius:32px 0px 32px 0px;padding:44px 40px;box-shadow:0 2px 24px rgba(0,0,0,0.8);">'
            . '<h1 style="margin:0 0 20px;font-size:32px;text-transform:uppercase;line-height:1.3;color:#d4a95e;font-weight:400;font-family:Arial,Helvetica,sans-serif;">' . esc_html($subject) . '</h1>'
            . '<p style="margin:0 0 32px;font-size:16px;line-height:1.6;color:#ffffff;">' . esc_html($intro) . '</p>'
            . '<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:999px;background-color:#d4a95e;">'
            . '<a href="' . esc_url($magic_url) . '" style="display:inline-block;padding:16px 34px;font-size:16px;font-weight:700;color:#080e10;text-decoration:none;border-radius:999px;font-family:Arial,Helvetica,sans-serif;">' . esc_html($button_label) . '</a>'
            . '</td></tr></table>'
            . '<p style="margin:36px 0 8px;font-size:14px;line-height:1.6;color:#a1a4a5;">' . esc_html($fallback_label) . '</p>'
            . '<p style="margin:0 0 32px;font-size:14px;line-height:1.6;word-break:break-all;"><a href="' . esc_url($magic_url) . '" style="color:rgba(161,164,165,0.6);text-decoration:underline;">' . esc_html($magic_url) . '</a></p>'
            . '<hr style="border:none;border-top:1px solid rgba(161,164,165,0.25);margin:0 0 20px;">'
            . '<p style="margin:0;font-size:12px;line-height:1.6;color:#a1a4a5;">' . esc_html($footer) . '</p>'
            . '</td></tr>'
            . '</table>'
            . '</td></tr></table>'
            . '</body></html>';

        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        add_filter('wp_mail_from_name', [$this, 'filter_mail_from_name']);
        $sent = wp_mail($user->user_email, $subject, $message);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        remove_filter('wp_mail_from_name', [$this, 'filter_mail_from_name']);

        if (!$sent) {
            $this->log_event('error', 'wp_mail() returned false sending the magic link to ' . $user->user_email . '.');
        }
    }

    public function set_html_mail_content_type(): string {
        return 'text/html';
    }

    public function filter_mail_from_name(): string {
        return (string) self::settings()['email_from_name'];
    }

    private function get_github_token(): string {
        if (!defined(self::GITHUB_TOKEN_CONSTANT_NAME)) {
            return '';
        }

        return (string) constant(self::GITHUB_TOKEN_CONSTANT_NAME);
    }

    private static function get_installed_version(): string {
        $data = get_file_data(__FILE__, ['Version' => 'Version']);
        return (string) ($data['Version'] ?? '');
    }

    /**
     * Fetches (and caches) the latest GitHub release. Returns an array shaped
     * ['tag_name', 'html_url', 'body', 'asset_id', 'asset_name', 'package_url']
     * or a WP_Error. Failures are negative-cached briefly so a transient
     * GitHub/network blip doesn't get retried on every single page load.
     */
    private function get_latest_github_release(bool $force_refresh = false) {
        if (!$force_refresh) {
            $cached = get_transient(self::UPDATE_RELEASE_CACHE_KEY);
            if ($cached !== false) {
                return $cached;
            }
        }

        // The repo is public: no token is required for either the version
        // check or the release download below. A token is only used, when
        // present, to raise GitHub's unauthenticated rate limit - it's an
        // optional boost, never a requirement to check for updates.
        $headers = [
            'Accept' => 'application/vnd.github+json',
            'X-GitHub-Api-Version' => '2022-11-28',
            'User-Agent' => 'WP-Magic-Link-Auth-Updater',
        ];
        $token = $this->get_github_token();
        if ($token !== '') {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        $response = wp_remote_get(
            sprintf('https://api.github.com/repos/%s/%s/releases/latest', self::GITHUB_OWNER, self::GITHUB_REPO),
            [
                'timeout' => 15,
                'headers' => $headers,
            ]
        );

        if (is_wp_error($response)) {
            $this->log_event('error', 'GitHub release check failed: ' . $response->get_error_message());
            set_transient(self::UPDATE_RELEASE_CACHE_KEY, $response, self::UPDATE_RELEASE_NEGATIVE_TTL);
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code !== 200 || !is_array($body)) {
            $error = new WP_Error('msv_magic_link_gh_release_http', 'GitHub release check returned HTTP ' . $code . '.');
            $this->log_event('error', $error->get_error_message());
            set_transient(self::UPDATE_RELEASE_CACHE_KEY, $error, self::UPDATE_RELEASE_NEGATIVE_TTL);
            return $error;
        }

        $tag = ltrim((string) ($body['tag_name'] ?? ''), 'v');
        if ($tag === '') {
            $error = new WP_Error('msv_magic_link_gh_no_tag', 'GitHub release response had no tag_name.');
            set_transient(self::UPDATE_RELEASE_CACHE_KEY, $error, self::UPDATE_RELEASE_NEGATIVE_TTL);
            return $error;
        }

        $asset = null;
        foreach ((array) ($body['assets'] ?? []) as $candidate) {
            if (isset($candidate['name']) && str_ends_with((string) $candidate['name'], '.zip')) {
                $asset = $candidate;
                break;
            }
        }

        if (!$asset) {
            $error = new WP_Error('msv_magic_link_no_asset', 'Latest GitHub release has no .zip asset attached.');
            $this->log_event('error', $error->get_error_message());
            set_transient(self::UPDATE_RELEASE_CACHE_KEY, $error, self::UPDATE_RELEASE_NEGATIVE_TTL);
            return $error;
        }

        $release = [
            'tag_name' => $tag,
            'html_url' => (string) ($body['html_url'] ?? ''),
            'body' => (string) ($body['body'] ?? ''),
            'asset_id' => (int) $asset['id'],
            'asset_name' => (string) $asset['name'],
            'package_url' => (string) ($asset['browser_download_url'] ?? ''),
        ];

        set_transient(self::UPDATE_RELEASE_CACHE_KEY, $release, self::UPDATE_RELEASE_CACHE_TTL);

        return $release;
    }

    /**
     * Self-service refresh of the disposable-domain list, for whoever runs
     * the election after this plugin is handed off - the developer may not
     * be involved by then, so this can't require a code change. Fetches the
     * source list fresh and stores it in DISPOSABLE_OPTION_KEY (autoload
     * false); a failed fetch NEVER wipes the currently active list, it just
     * leaves it as-is and reports the error.
     *
     * @return array{count:int}|WP_Error
     */
    public function refresh_disposable_list_from_source() {
        $response = wp_remote_get(self::DISPOSABLE_BLOCKLIST_URL, ['timeout' => 20]);

        if (is_wp_error($response)) {
            $this->log_event('error', 'Disposable-domain list refresh failed: ' . $response->get_error_message());
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code !== 200 || trim($body) === '') {
            $error = new WP_Error('msv_magic_link_disposable_http', 'Disposable-domain list refresh returned HTTP ' . $code . '.');
            $this->log_event('error', $error->get_error_message());
            return $error;
        }

        $domains = [];
        foreach (preg_split('/\r\n|\r|\n/', $body) as $line) {
            $line = strtolower(trim($line));
            if ($line !== '' && $line[0] !== '#') {
                $domains[] = $line;
            }
        }

        if (empty($domains)) {
            $error = new WP_Error('msv_magic_link_disposable_empty', 'Disposable-domain list refresh returned no domains.');
            $this->log_event('error', $error->get_error_message());
            return $error;
        }

        update_option(self::DISPOSABLE_OPTION_KEY, [
            'domains' => $domains,
            'count' => count($domains),
            'refreshed' => time(),
        ], false);

        $this->log_event('info', 'Disposable-domain list refreshed: ' . count($domains) . ' domains.');

        return ['count' => count($domains)];
    }

    public function check_for_update($transient) {
        // Deliberately NOT bailing out when $transient->checked is empty -
        // this filter also fires when WP core resets the transient to a
        // bare object to force a recheck, and checked isn't populated yet
        // at that point. Bailing there would return the transient
        // unmodified, and that incomplete state gets cached, producing
        // exactly the "list page says update available, but Update Now
        // says already at latest version" contradiction (both just read
        // whatever's currently cached; neither forces a fresh check).
        // get_installed_version() is a fully reliable source on its own,
        // so there's no need to depend on WP's own bookkeeping here.
        if (!is_object($transient)) {
            $transient = new stdClass();
        }

        $plugin_file = plugin_basename(__FILE__);
        $release = $this->get_latest_github_release();
        if (!is_array($release)) {
            return $transient;
        }

        $installed = self::get_installed_version();

        if (version_compare($release['tag_name'], $installed, '>')) {
            $item = new stdClass();
            $item->slug = dirname($plugin_file);
            $item->plugin = $plugin_file;
            $item->new_version = $release['tag_name'];
            $item->url = $release['html_url'];
            $item->package = $release['package_url'];
            $item->requires_php = '8.4';
            $transient->response[$plugin_file] = $item;
            unset($transient->no_update[$plugin_file]);
        } else {
            unset($transient->response[$plugin_file]);
            $transient->no_update[$plugin_file] = (object) [
                'slug' => dirname($plugin_file),
                'plugin' => $plugin_file,
                'new_version' => $installed,
            ];
        }

        return $transient;
    }

    /**
     * Powers WordPress core's own native "View version X.Y.Z details" popup
     * on the Plugins list page. Not optional once check_for_update() is
     * wired up: core renders that popup link automatically whenever the
     * update transient has a response for this plugin, and without this
     * handler it would query the (nonexistent, for us) wordpress.org API.
     */
    public function plugins_api_handler($result, $action, $args) {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== dirname(plugin_basename(__FILE__))) {
            return $result;
        }

        $release = $this->get_latest_github_release();
        if (!is_array($release)) {
            return $result;
        }

        $info = new stdClass();
        $info->name = __('WP Magic Link Auth', 'msv-magic-link-auth');
        $info->slug = dirname(plugin_basename(__FILE__));
        $info->version = $release['tag_name'];
        $info->author = '<a href="mailto:igor@igibits.com">igor@igibits.com</a>';
        $info->homepage = $release['html_url'];
        $info->requires_php = '8.4';
        $info->download_link = $release['package_url'];
        $info->sections = [
            'description' => esc_html__('Passwordless magic-link authentication with rate limiting, an optional protected page, and a disposable-email blocklist.', 'msv-magic-link-auth'),
            'changelog' => wpautop(esc_html($release['body'])),
        ];

        return $info;
    }

    /**
     * Used only by the settings page's button row/status line — forces a
     * reasonably fresh check (bypassing the update-check transient cache,
     * since this only runs on a rare, deliberate admin page load) and
     * distinguishes "up to date" from "couldn't check" rather than letting
     * a failed GitHub lookup silently read as "up to date".
     */
    private function get_update_status_for_display(): array {
        if (!function_exists('wp_update_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $core_transient = get_site_transient('update_plugins');
        if (!$core_transient || empty($core_transient->last_checked) || (time() - $core_transient->last_checked) > HOUR_IN_SECONDS) {
            wp_update_plugins();
        }

        $release = $this->get_latest_github_release(true);
        if (is_wp_error($release)) {
            return [
                'available' => false,
                'message' => 'Could not check for updates — see log below.',
                'url' => '',
            ];
        }

        $installed = self::get_installed_version();
        if (version_compare($release['tag_name'], $installed, '<=')) {
            return [
                'available' => false,
                'message' => 'You have the latest version (v' . $installed . ').',
                'url' => '',
            ];
        }

        $plugin_file = plugin_basename(__FILE__);
        $url = wp_nonce_url(
            self_admin_url('update.php?action=upgrade-plugin&plugin=' . rawurlencode($plugin_file)),
            'upgrade-plugin_' . $plugin_file
        );

        return [
            'available' => true,
            'message' => 'Update available: v' . $release['tag_name'],
            'url' => $url,
        ];
    }

    public function register_settings_page(): void {
        add_options_page(
            __('WP Magic Link Auth', 'msv-magic-link-auth'),
            __('WP Magic Link Auth', 'msv-magic-link-auth'),
            'manage_options',
            self::SETTINGS_PAGE_SLUG,
            [$this, 'render_settings_page']
        );
    }

    private function sanitize_path(string $path): string {
        $path = trim(sanitize_text_field($path));
        if ($path === '' || $path === '/') {
            return '/';
        }

        return untrailingslashit('/' . ltrim($path, '/'));
    }

    /**
     * Read-only, admin-render-time only: best-effort match of a legacy
     * free-text path to a published Page, so the picker dropdown
     * pre-selects the right page the first time this renders after
     * upgrading from free-text paths. Never called from settings()/runtime
     * - only from render_settings_page(). Self-migrating: once the admin
     * saves once via the picker the stored value becomes numeric and this
     * is skipped forever after, the same self-migrating pattern already
     * used for pre-'ts' log entries in log_event().
     */
    private function match_legacy_path_to_page_id(string $stored): int {
        $target = untrailingslashit('/' . ltrim($stored, '/'));
        foreach (get_pages(['post_status' => 'publish']) as $page) {
            $permalink = get_permalink($page);
            if (!$permalink) {
                continue;
            }
            $page_path = untrailingslashit('/' . ltrim((string) wp_parse_url($permalink, PHP_URL_PATH), '/'));
            if ($page_path === $target) {
                return (int) $page->ID;
            }
        }
        return 0;
    }

    /**
     * Figures out how a stored path/page-ID setting should be displayed in
     * the settings-page picker: which dropdown option is selected, and what
     * (if anything) belongs in the "Custom / other" fallback text input.
     */
    private function page_picker_display_state(string $stored, bool $allow_inherit): array {
        if ($allow_inherit && $stored === '') {
            return ['mode' => 'inherit', 'page_id' => 0, 'custom' => ''];
        }

        if ($stored !== '' && ctype_digit($stored)) {
            if (get_post_status((int) $stored) === 'publish') {
                return ['mode' => 'page', 'page_id' => (int) $stored, 'custom' => ''];
            }
            return ['mode' => 'custom', 'page_id' => 0, 'custom' => '']; // page since deleted/unpublished
        }

        $matched = $stored !== '' ? $this->match_legacy_path_to_page_id($stored) : 0;
        if ($matched > 0) {
            return ['mode' => 'page', 'page_id' => $matched, 'custom' => $stored];
        }

        return ['mode' => 'custom', 'page_id' => 0, 'custom' => $stored];
    }

    /**
     * Renders a <select> of published pages via wp_dropdown_pages(), with a
     * "Custom / other" option (value "0", never a real post ID) and,
     * optionally, a "Use request page path" option (value "-1") for the
     * confirm-page field's inherit behavior. Neither synthetic option is
     * auto-selected by core, so the correct one is marked selected here by
     * matching the exact literal tag wp_dropdown_pages() emits for it.
     */
    private function render_page_dropdown(string $name, string $mode, int $selected_page_id, bool $allow_inherit): string {
        $args = [
            'name' => $name,
            'id' => $name,
            'class' => 'msv-page-picker',
            'echo' => 0,
            'selected' => $selected_page_id,
            'show_option_none' => esc_html__('— Custom / other (enter path manually) —', 'msv-magic-link-auth'),
            'option_none_value' => '0',
        ];
        if ($allow_inherit) {
            $args['show_option_no_change'] = esc_html__('— Use request page path (default) —', 'msv-magic-link-auth');
        }

        $dropdown = wp_dropdown_pages($args);

        if ($dropdown === '') {
            // No published pages site-wide: wp_dropdown_pages() returns ''
            // even with show_option_* set, so build a minimal fallback by hand.
            $dropdown = '<select name="' . esc_attr($name) . '" id="' . esc_attr($name) . '" class="msv-page-picker">'
                . ($allow_inherit ? '<option value="-1">' . esc_html__('— Use request page path (default) —', 'msv-magic-link-auth') . '</option>' : '')
                . '<option value="0">' . esc_html__('— Custom / other (enter path manually) —', 'msv-magic-link-auth') . '</option></select>';
        }

        if ($mode === 'custom') {
            $dropdown = str_replace('<option value="0">', '<option value="0" selected="selected">', $dropdown);
        } elseif ($mode === 'inherit') {
            $dropdown = str_replace('<option value="-1">', '<option value="-1" selected="selected">', $dropdown);
        }

        return $dropdown;
    }

    /**
     * Renders the shared mode/once/repeating schedule fieldset used by both
     * the TotalPoll purge schedule and the voter-deletion schedule - same
     * field shape, different $_POST field-name prefix (see
     * save_schedule_from_post()) and save-button name.
     */
    private function render_schedule_fieldset(string $field_prefix, array $schedule, string $save_button_name, string $legend): string {
        $format_ts = static function (?int $ts, string $never_label): string {
            return $ts === null ? $never_label : wp_date('Y-m-d H:i', $ts);
        };

        ob_start();
        ?>
        <fieldset class="msv-schedule-fieldset" data-schedule-prefix="<?php echo esc_attr($field_prefix); ?>">
            <legend><?php echo esc_html($legend); ?></legend>
            <p class="description">
                <?php
                printf(
                    /* translators: %s: site timezone name, e.g. Europe/Zurich */
                    esc_html__('Times below are in your site\'s timezone (%s).', 'msv-magic-link-auth'),
                    esc_html(wp_timezone()->getName())
                );
                ?>
            </p>
            <label>
                <input type="radio" class="msv-schedule-mode-radio" name="<?php echo esc_attr($field_prefix); ?>_schedule_mode" value="off" <?php checked($schedule['mode'], 'off'); ?>>
                <?php esc_html_e('Manual only (no automatic schedule)', 'msv-magic-link-auth'); ?>
            </label><br>
            <label>
                <input type="radio" class="msv-schedule-mode-radio" name="<?php echo esc_attr($field_prefix); ?>_schedule_mode" value="once" <?php checked($schedule['mode'], 'once'); ?>>
                <?php esc_html_e('Run once at a specific date and time', 'msv-magic-link-auth'); ?>
            </label>
            <div class="msv-schedule-group" data-schedule-group="once" <?php echo $schedule['mode'] !== 'once' ? 'hidden' : ''; ?>>
                <input type="datetime-local" name="<?php echo esc_attr($field_prefix); ?>_once_at" value="<?php echo esc_attr($schedule['once_at']); ?>">
            </div>
            <label>
                <input type="radio" class="msv-schedule-mode-radio" name="<?php echo esc_attr($field_prefix); ?>_schedule_mode" value="repeating" <?php checked($schedule['mode'], 'repeating'); ?>>
                <?php esc_html_e('Repeat automatically', 'msv-magic-link-auth'); ?>
            </label>
            <div class="msv-schedule-group" data-schedule-group="repeating" <?php echo $schedule['mode'] !== 'repeating' ? 'hidden' : ''; ?>>
                <?php
                printf(
                    /* translators: 1: number-of-days input, 2: start date/time input, 3: end date/time input */
                    esc_html__('Every %1$s days, from %2$s to %3$s', 'msv-magic-link-auth'),
                    '<input type="number" min="1" style="width:5em" name="' . esc_attr($field_prefix) . '_repeat_interval_days" value="' . esc_attr((string) max(1, (int) $schedule['repeat_interval_days'])) . '">',
                    '<input type="datetime-local" name="' . esc_attr($field_prefix) . '_repeat_start_at" value="' . esc_attr($schedule['repeat_start_at']) . '">',
                    '<input type="datetime-local" name="' . esc_attr($field_prefix) . '_repeat_end_at" value="' . esc_attr($schedule['repeat_end_at']) . '">'
                );
                ?>
            </div>
        </fieldset>
        <p class="description">
            <?php
            printf(
                /* translators: %s: formatted next-run date/time, or "Not scheduled" */
                esc_html__('Next scheduled run: %s', 'msv-magic-link-auth'),
                '<strong>' . esc_html($format_ts($schedule['next_run_ts'], __('Not scheduled', 'msv-magic-link-auth'))) . '</strong>'
            );
            ?>
            <br>
            <?php if ($schedule['last_run_ts'] !== null): ?>
                <?php
                printf(
                    /* translators: 1: formatted last-run date/time, 2: status word (success/error/skipped), 3: short diagnostic message */
                    esc_html__('Last run: %1$s — %2$s (%3$s)', 'msv-magic-link-auth'),
                    esc_html($format_ts($schedule['last_run_ts'], '')),
                    esc_html($schedule['last_run_status']),
                    esc_html($schedule['last_run_message'])
                );
                ?>
            <?php else: ?>
                <?php esc_html_e('Last run: never.', 'msv-magic-link-auth'); ?>
            <?php endif; ?>
        </p>
        <?php if ($schedule['mode'] !== 'off' && defined('DISABLE_WP_CRON') && DISABLE_WP_CRON): ?>
            <div class="notice notice-warning inline"><p><?php esc_html_e('WP-Cron is disabled on this site (DISABLE_WP_CRON), so this schedule will not run unless a real system cron job is configured to trigger it.', 'msv-magic-link-auth'); ?></p></div>
        <?php endif; ?>
        <p>
            <button type="submit" name="<?php echo esc_attr($save_button_name); ?>" value="1" form="msv-settings-form" class="button"><?php esc_html_e('Save schedule', 'msv-magic-link-auth'); ?></button>
        </p>
        <?php
        return ob_get_clean();
    }

    /**
     * Locates TotalPoll Pro's raw vote-log table (holds voter IP + user
     * agent per vote action, separate from the aggregate vote-count table).
     * The table prefix always comes from $wpdb->prefix - never hardcoded -
     * since hosts vary (e.g. Infomaniak's own wp_<siteid>_ style prefixes).
     * Verifies both the table AND the IP column actually exist before ever
     * offering the clear-IPs action, so this degrades gracefully (and
     * visibly, via the settings-page status line) on any site where
     * TotalPoll isn't installed, isn't Pro, or has a differently-named
     * table/column - never guesses, never silently no-ops.
     */
    private function get_totalpoll_log_table(string $suffix, string $ip_column): ?string {
        global $wpdb;

        $suffix = preg_replace('/[^a-zA-Z0-9_]/', '', $suffix);
        $column = preg_replace('/[^a-zA-Z0-9_]/', '', $ip_column);
        if ($suffix === '' || $column === '') {
            return null;
        }

        $table = $wpdb->prefix . $suffix;

        $found_table = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
        if ($found_table !== $table) {
            return null;
        }

        // $table is safe to interpolate here: built from $wpdb->prefix (WP
        // core, trusted) plus $suffix, which was stripped above to
        // [a-zA-Z0-9_] only - $wpdb->prepare() can't parameterize identifiers,
        // only values, so this is the standard WordPress pattern for a
        // dynamic-but-sanitized table/column name.
        $found_column = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM `$table` LIKE %s", $column));
        if ($found_column === null) {
            return null;
        }

        return $table;
    }

    private function count_totalpoll_ips(string $table, string $ip_column): int {
        global $wpdb;
        $column = preg_replace('/[^a-zA-Z0-9_]/', '', $ip_column);
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM `$table` WHERE `$column` IS NOT NULL AND `$column` != ''");
    }

    /**
     * Nulls out (never deletes) the IP column on every row of TotalPoll's
     * vote-log table. Rows are kept intentionally: TotalPoll's own
     * one-vote-per-user enforcement counts rows in this same table by
     * user_id, so deleting rows outright could let a repeat vote go
     * undetected later. Vote counts/results live entirely in a separate
     * aggregate table with no personal data at all, so this has zero
     * effect on results either way.
     *
     * @return int|WP_Error Number of rows affected, or WP_Error on failure.
     */
    public function clear_totalpoll_ips(string $table, string $ip_column) {
        global $wpdb;
        $column = preg_replace('/[^a-zA-Z0-9_]/', '', $ip_column);

        $affected = $wpdb->query("UPDATE `$table` SET `$column` = NULL WHERE `$column` IS NOT NULL");

        if ($affected === false) {
            $message = $wpdb->last_error !== '' ? $wpdb->last_error : 'Unknown database error.';
            $this->log_event('error', 'TotalPoll IP clear failed: ' . $message);
            return new WP_Error('msv_magic_link_totalpoll_clear_failed', $message);
        }

        $this->log_event('info', 'TotalPoll voter IPs cleared: ' . (int) $affected . ' row(s) in ' . $table . '.');

        return (int) $affected;
    }

    private function persist_totalpoll_table_settings(string $suffix, string $column): void {
        $existing = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());
        $existing['totalpoll_table_suffix'] = $suffix;
        $existing['totalpoll_ip_column'] = $column;
        update_option(self::OPTION_KEY, $existing);
    }

    public function run_scheduled_totalpoll_purge(): void {
        $settings = self::settings();
        $table = $this->get_totalpoll_log_table($settings['totalpoll_table_suffix'], $settings['totalpoll_ip_column']);

        $schedule = $this->get_schedule(self::TOTALPOLL_SCHEDULE_OPTION_KEY);

        if ($table === null) {
            $this->log_event('warning', 'Scheduled TotalPoll IP purge skipped: table/column not found.');
            $schedule['last_run_status'] = 'skipped';
            $schedule['last_run_message'] = 'Table/column not found.';
        } else {
            $result = $this->clear_totalpoll_ips($table, $settings['totalpoll_ip_column']);
            if (is_wp_error($result)) {
                $schedule['last_run_status'] = 'error';
                $schedule['last_run_message'] = $result->get_error_message();
            } else {
                $schedule['last_run_status'] = 'success';
                $schedule['last_run_message'] = $result . ' row(s) cleared.';
            }
        }

        $schedule['last_run_ts'] = time();
        update_option(self::TOTALPOLL_SCHEDULE_OPTION_KEY, $schedule, false);

        // Re-arms from the freshly-saved state; for a repeating schedule this
        // computes and schedules the next occurrence (or leaves it unscheduled
        // once the end date has passed) - for 'once' this just consumes it.
        $this->arm_schedule(self::TOTALPOLL_SCHEDULE_OPTION_KEY, self::TOTALPOLL_CRON_HOOK);
    }

    /**
     * Returns every user whose role is EXACTLY ['subscriber'] - never a user
     * who also holds another role (admin/editor/etc via some other plugin),
     * since WP_User_Query's 'role' param matches "has this role among
     * possibly others", not an exact-match. This same exactness check is
     * applied for both matching modes below, including tag-based, since a
     * tag only records how an account was created, not its current role.
     */
    private function get_voter_user_ids_by_role(): array {
        $users = get_users(['role' => 'subscriber', 'fields' => 'all']);
        $ids = [];
        foreach ($users as $user) {
            if ($user->roles === ['subscriber']) {
                $ids[] = $user->ID;
            }
        }
        return $ids;
    }

    private function get_voter_user_ids_by_tag(): array {
        $candidate_ids = get_users([
            'meta_key' => self::VOTER_CREATED_META_KEY,
            'fields' => 'ID',
        ]);
        if (empty($candidate_ids)) {
            return [];
        }

        $users = get_users(['include' => $candidate_ids, 'fields' => 'all']);
        $ids = [];
        foreach ($users as $user) {
            if ($user->roles === ['subscriber']) {
                $ids[] = $user->ID;
            }
        }
        return $ids;
    }

    private function get_voter_user_ids(string $match_mode): array {
        return $match_mode === 'tag' ? $this->get_voter_user_ids_by_tag() : $this->get_voter_user_ids_by_role();
    }

    /**
     * Displayed as a live preview on the settings page, which (since tabs are
     * shown/hidden client-side with no re-fetch) renders unconditionally on
     * every page load regardless of which tab is active. get_users() can be
     * a heavy query on a site with many accounts, so the preview count is
     * cached briefly - this only affects what's displayed; delete_voters()
     * always re-fetches its own fresh candidate list and never trusts this
     * cached number.
     */
    public function count_voters(string $match_mode): int {
        $cache_key = 'msv_magic_link_voter_count_' . $match_mode;
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return (int) $cached;
        }

        $count = count($this->get_voter_user_ids($match_mode));
        set_transient($cache_key, $count, MINUTE_IN_SECONDS);

        return $count;
    }

    /**
     * Always re-fetches its own candidate list rather than accepting one
     * from a caller, so a stale on-page preview count can never cause a
     * mismatch between what was shown and what actually gets deleted -
     * the live count and the deletion always see the same fresh query.
     * Single-site only (no multisite wpmu_delete_user() handling).
     */
    public function delete_voters(string $match_mode): int {
        if (!function_exists('wp_delete_user')) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }

        $ids = $this->get_voter_user_ids($match_mode);
        $deleted = 0;
        foreach ($ids as $id) {
            if (wp_delete_user($id)) {
                $deleted++;
            }
        }

        $this->log_event('info', 'Voter accounts deleted (' . $match_mode . ' match): ' . $deleted . ' of ' . count($ids) . ' candidate(s).');

        return $deleted;
    }

    public function run_scheduled_voter_delete(): void {
        $settings = self::settings();
        $schedule = $this->get_schedule(self::VOTER_DELETE_SCHEDULE_OPTION_KEY);

        $deleted = $this->delete_voters($settings['voter_delete_match_mode']);
        $schedule['last_run_status'] = 'success';
        $schedule['last_run_message'] = $deleted . ' voter account(s) deleted.';
        $schedule['last_run_ts'] = time();
        update_option(self::VOTER_DELETE_SCHEDULE_OPTION_KEY, $schedule, false);

        $this->arm_schedule(self::VOTER_DELETE_SCHEDULE_OPTION_KEY, self::VOTER_DELETE_CRON_HOOK);
    }

    /**
     * Shared save handler for both schedule forms (identical field shape,
     * different $_POST field-name prefix). Only rejects genuinely blank or
     * unparseable input - a semantically infeasible-but-well-formed schedule
     * (end date before start date, a one-time date already in the past) is
     * saved as typed and simply resolves to "nothing scheduled" via
     * arm_schedule(), visible immediately in the next-run status line,
     * rather than being blocked here. Returns an error message, or '' on
     * success.
     */
    private function save_schedule_from_post(string $option_key, string $cron_hook, string $field_prefix): string {
        $existing = $this->get_schedule($option_key);

        $mode = sanitize_key(wp_unslash($_POST[$field_prefix . '_schedule_mode'] ?? 'off'));
        if (!in_array($mode, ['off', 'once', 'repeating'], true)) {
            $mode = 'off';
        }

        // A field belonging to a mode other than the one currently selected
        // may legitimately be absent from $_POST (disabled by JS to match
        // the active mode) - fall back to the previously-stored value rather
        // than blanking it, exactly like the Turnstile-keys/dev-mode fields
        // elsewhere on this page.
        $once_at = array_key_exists($field_prefix . '_once_at', $_POST)
            ? sanitize_text_field(wp_unslash($_POST[$field_prefix . '_once_at']))
            : $existing['once_at'];
        $repeat_start_at = array_key_exists($field_prefix . '_repeat_start_at', $_POST)
            ? sanitize_text_field(wp_unslash($_POST[$field_prefix . '_repeat_start_at']))
            : $existing['repeat_start_at'];
        $repeat_end_at = array_key_exists($field_prefix . '_repeat_end_at', $_POST)
            ? sanitize_text_field(wp_unslash($_POST[$field_prefix . '_repeat_end_at']))
            : $existing['repeat_end_at'];
        $repeat_interval_days = array_key_exists($field_prefix . '_repeat_interval_days', $_POST)
            ? max(1, absint($_POST[$field_prefix . '_repeat_interval_days']))
            : $existing['repeat_interval_days'];

        if ($mode === 'once' && $this->parse_site_local_datetime($once_at) === null) {
            return __('Could not save the schedule: please choose a valid date and time.', 'msv-magic-link-auth');
        }
        if ($mode === 'repeating' && ($this->parse_site_local_datetime($repeat_start_at) === null || $this->parse_site_local_datetime($repeat_end_at) === null)) {
            return __('Could not save the schedule: please choose valid start and end dates.', 'msv-magic-link-auth');
        }

        $schedule = $existing;
        $schedule['mode'] = $mode;
        $schedule['once_at'] = $once_at;
        $schedule['repeat_start_at'] = $repeat_start_at;
        $schedule['repeat_interval_days'] = $repeat_interval_days;
        $schedule['repeat_end_at'] = $repeat_end_at;
        update_option($option_key, $schedule, false);

        $this->arm_schedule($option_key, $cron_hook);

        return '';
    }

    public function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $tabs = ['setup', 'email', 'messaging', 'maintenance', 'log'];
        $notice = '';
        $error_notice = '';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!isset($_POST['msv_magic_settings_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['msv_magic_settings_nonce'])), self::SETTINGS_NONCE_ACTION)) {
                wp_die(esc_html__('Invalid request.', 'msv-magic-link-auth'), 403);
            }

            if (isset($_POST['msv_magic_clear_log'])) {
                delete_option(self::LOG_OPTION_KEY);
                $notice = __('Log cleared.', 'msv-magic-link-auth');
            } elseif (isset($_POST['msv_magic_refresh_disposable'])) {
                $result = $this->refresh_disposable_list_from_source();
                if (is_wp_error($result)) {
                    /* translators: %s: error message */
                    $error_notice = sprintf(__('Could not refresh the list: %s The current list was left unchanged.', 'msv-magic-link-auth'), $result->get_error_message());
                } else {
                    /* translators: %d: number of domains loaded */
                    $notice = sprintf(__('Disposable-domain list refreshed: %d domains.', 'msv-magic-link-auth'), (int) $result['count']);
                }
            } elseif (isset($_POST['msv_magic_clear_totalpoll_ips'])) {
                $tp_suffix = sanitize_text_field(wp_unslash($_POST['totalpoll_table_suffix'] ?? 'totalpoll_log'));
                $tp_column = sanitize_text_field(wp_unslash($_POST['totalpoll_ip_column'] ?? 'ip'));
                $tp_table = $this->get_totalpoll_log_table($tp_suffix, $tp_column);

                if ($tp_table === null) {
                    $error_notice = __('Could not find that table/column - nothing was changed. Check the table name and column name below.', 'msv-magic-link-auth');
                } else {
                    $tp_result = $this->clear_totalpoll_ips($tp_table, $tp_column);
                    if (is_wp_error($tp_result)) {
                        /* translators: %s: error message */
                        $error_notice = sprintf(__('Could not clear IPs: %s', 'msv-magic-link-auth'), $tp_result->get_error_message());
                    } else {
                        /* translators: %d: number of rows affected */
                        $notice = sprintf(__('Cleared the IP address from %d TotalPoll log entries.', 'msv-magic-link-auth'), $tp_result);
                    }
                }

                // Persist the (possibly just-adjusted) table/column names for
                // next time, regardless of whether the clear itself succeeded.
                $this->persist_totalpoll_table_settings($tp_suffix, $tp_column);
            } elseif (isset($_POST['msv_magic_check_totalpoll'])) {
                $tp_suffix = sanitize_text_field(wp_unslash($_POST['totalpoll_table_suffix'] ?? 'totalpoll_log'));
                $tp_column = sanitize_text_field(wp_unslash($_POST['totalpoll_ip_column'] ?? 'ip'));
                $this->persist_totalpoll_table_settings($tp_suffix, $tp_column);

                $tp_table = $this->get_totalpoll_log_table($tp_suffix, $tp_column);
                if ($tp_table === null) {
                    $error_notice = __('Checks failed: could not find that table/column. Check the table name and column name below.', 'msv-magic-link-auth');
                } else {
                    $notice = sprintf(
                        /* translators: 1: database table name, 2: number of rows currently storing an IP address */
                        __('Checks passed: table %1$s found, %2$d entries currently store an IP address.', 'msv-magic-link-auth'),
                        $tp_table,
                        $this->count_totalpoll_ips($tp_table, $tp_column)
                    );
                }
            } elseif (isset($_POST['msv_magic_save_totalpoll_schedule'])) {
                $error_notice = $this->save_schedule_from_post(self::TOTALPOLL_SCHEDULE_OPTION_KEY, self::TOTALPOLL_CRON_HOOK, 'totalpoll');
                if ($error_notice === '') {
                    $notice = __('IP-purge schedule saved.', 'msv-magic-link-auth');
                }
            } elseif (isset($_POST['msv_magic_save_voter_delete_schedule'])) {
                $error_notice = $this->save_schedule_from_post(self::VOTER_DELETE_SCHEDULE_OPTION_KEY, self::VOTER_DELETE_CRON_HOOK, 'voter_delete');
                if ($error_notice === '') {
                    $notice = __('Voter-deletion schedule saved.', 'msv-magic-link-auth');
                }
            } elseif (isset($_POST['msv_magic_delete_voters_now'])) {
                $match_mode = sanitize_key(wp_unslash($_POST['voter_delete_match_mode'] ?? self::settings()['voter_delete_match_mode']));
                if (!in_array($match_mode, ['role', 'tag'], true)) {
                    $match_mode = 'role';
                }
                $deleted = $this->delete_voters($match_mode);
                /* translators: %d: number of accounts deleted */
                $notice = sprintf(__('Deleted %d voter account(s).', 'msv-magic-link-auth'), $deleted);
            } else {
                // Existing stored values, used as the fallback whenever a field
                // is absent from $_POST - this happens legitimately for any
                // <input disabled> (dev-mode/Turnstile pairs), since disabled
                // controls are excluded from submitted form data by the HTML
                // spec. Without this fallback, saving while e.g. Turnstile is
                // off would silently blank the stored keys via `?? ''`.
                $existing = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());

                $request_page_id = isset($_POST['request_page_id']) ? sanitize_text_field(wp_unslash($_POST['request_page_id'])) : '0';
                $request_page_path = (ctype_digit($request_page_id) && (int) $request_page_id > 0 && get_post_status((int) $request_page_id) === 'publish')
                    ? $request_page_id
                    : $this->sanitize_path(wp_unslash($_POST['request_page_custom'] ?? ''));

                $vote_page_id = isset($_POST['vote_page_id']) ? sanitize_text_field(wp_unslash($_POST['vote_page_id'])) : '0';
                $vote_page_path = (ctype_digit($vote_page_id) && (int) $vote_page_id > 0 && get_post_status((int) $vote_page_id) === 'publish')
                    ? $vote_page_id
                    : $this->sanitize_path(wp_unslash($_POST['vote_page_custom'] ?? ''));

                // "-1" preserves the existing "blank = inherit request_page_path" behavior.
                $confirm_page_id = isset($_POST['confirm_page_id']) ? sanitize_text_field(wp_unslash($_POST['confirm_page_id'])) : '-1';
                if ($confirm_page_id === '-1') {
                    $confirm_page_path = '';
                } elseif (ctype_digit($confirm_page_id) && (int) $confirm_page_id > 0 && get_post_status((int) $confirm_page_id) === 'publish') {
                    $confirm_page_path = $confirm_page_id;
                } else {
                    $confirm_raw = trim(sanitize_text_field(wp_unslash($_POST['confirm_page_custom'] ?? '')));
                    $confirm_page_path = $confirm_raw === '' ? '' : $this->sanitize_path($confirm_raw);
                }

                update_option(self::OPTION_KEY, [
                    'site_key' => array_key_exists('site_key', $_POST) ? sanitize_text_field(wp_unslash($_POST['site_key'])) : $existing['site_key'],
                    'secret_key' => array_key_exists('secret_key', $_POST) ? sanitize_text_field(wp_unslash($_POST['secret_key'])) : $existing['secret_key'],
                    'request_page_path' => $request_page_path,
                    'confirm_page_path' => $confirm_page_path,
                    'vote_page_path' => $vote_page_path,
                    'max_attempts_per_hour' => max(1, absint($_POST['max_attempts_per_hour'] ?? 3)),
                    'token_ttl' => array_key_exists('token_ttl_hours', $_POST) ? max(1, absint($_POST['token_ttl_hours'])) * HOUR_IN_SECONDS : $existing['token_ttl'],
                    'dev_mode' => isset($_POST['dev_mode']),
                    'dev_mode_minutes' => array_key_exists('dev_mode_minutes', $_POST) ? max(1, absint($_POST['dev_mode_minutes'])) : $existing['dev_mode_minutes'],
                    'email_from_name' => sanitize_text_field(wp_unslash($_POST['email_from_name'] ?? '')),
                    'email_subject' => sanitize_text_field(wp_unslash($_POST['email_subject'] ?? '')),
                    'turnstile_enabled' => isset($_POST['turnstile_enabled']),
                    'msg_sent' => sanitize_textarea_field(wp_unslash($_POST['msg_sent'] ?? '')),
                    'msg_invalid' => sanitize_textarea_field(wp_unslash($_POST['msg_invalid'] ?? '')),
                    'msg_rate_limited' => sanitize_textarea_field(wp_unslash($_POST['msg_rate_limited'] ?? '')),
                    'msg_captcha_failed' => sanitize_textarea_field(wp_unslash($_POST['msg_captcha_failed'] ?? '')),
                    'msg_email_required' => sanitize_textarea_field(wp_unslash($_POST['msg_email_required'] ?? '')),
                    'msg_confirm' => sanitize_textarea_field(wp_unslash($_POST['msg_confirm'] ?? '')),
                    'msg_disposable' => sanitize_textarea_field(wp_unslash($_POST['msg_disposable'] ?? '')),
                    'custom_disposable_domains' => sanitize_textarea_field(wp_unslash($_POST['custom_disposable_domains'] ?? '')),
                    'disposable_allowlist' => sanitize_textarea_field(wp_unslash($_POST['disposable_allowlist'] ?? '')),
                    'log_retention_days' => max(1, absint($_POST['log_retention_days'] ?? 3)),
                    'totalpoll_table_suffix' => sanitize_text_field(wp_unslash($_POST['totalpoll_table_suffix'] ?? 'totalpoll_log')),
                    'totalpoll_ip_column' => sanitize_text_field(wp_unslash($_POST['totalpoll_ip_column'] ?? 'ip')),
                    'voter_delete_match_mode' => in_array($_POST['voter_delete_match_mode'] ?? '', ['role', 'tag'], true)
                        ? sanitize_key($_POST['voter_delete_match_mode'])
                        : $existing['voter_delete_match_mode'],
                ]);
                $notice = __('Settings saved.', 'msv-magic-link-auth');
            }
        }

        $initial_tab = ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['msv_active_tab'] ?? '', $tabs, true))
            ? sanitize_key(wp_unslash($_POST['msv_active_tab']))
            : $tabs[0];

        // Deliberately NOT self::settings() here: that resolves page IDs to
        // paths and applies the dev-mode minutes override to token_ttl,
        // which would make this form display (and, on save, persist) the
        // wrong values. This page always shows/edits the real stored config.
        $settings = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());
        $log = get_option(self::LOG_OPTION_KEY, []);
        if (!is_array($log)) {
            $log = [];
        }
        $update = $this->get_update_status_for_display();
        $disposable_status = get_option(self::DISPOSABLE_OPTION_KEY, []);

        $request_state = $this->page_picker_display_state((string) $settings['request_page_path'], false);
        $vote_state = $this->page_picker_display_state((string) $settings['vote_page_path'], false);
        $confirm_state = $this->page_picker_display_state((string) $settings['confirm_page_path'], true);
        ?>
        <div class="wrap msv-settings-wrap<?php echo is_admin_bar_showing() ? ' msv-has-adminbar' : ''; ?>">

            <div class="msv-sticky-header">
                <h1><strong><?php esc_html_e('WP Magic Link Auth', 'msv-magic-link-auth'); ?></strong></h1>
                <p><?php esc_html_e('Developed by igor@igibits.com', 'msv-magic-link-auth'); ?></p>
                <?php if ($notice): ?>
                    <div class="notice notice-success is-dismissible"><p><?php echo esc_html($notice); ?></p></div>
                <?php endif; ?>
                <?php if ($error_notice): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html($error_notice); ?></p></div>
                <?php endif; ?>
                <?php if (!empty($settings['dev_mode'])): ?>
                    <div class="notice notice-warning">
                        <p>
                            <?php
                            printf(
                                /* translators: 1: "Development mode is ON —" (bold), 2: number of minutes */
                                esc_html__('%1$s Magic links expire after %2$d minute(s) regardless of the setting below. Turn this off before going live.', 'msv-magic-link-auth'),
                                '<strong>' . esc_html__('Development mode is ON —', 'msv-magic-link-auth') . '</strong>',
                                (int) max(1, absint($settings['dev_mode_minutes']))
                            );
                            ?>
                        </p>
                    </div>
                <?php endif; ?>
                <p style="display:flex;gap:8px;align-items:center;">
                    <?php submit_button(__('Save settings', 'msv-magic-link-auth'), 'primary', 'submit', false, ['form' => 'msv-settings-form']); ?>
                    <?php if ($update['available']): ?>
                        <a href="<?php echo esc_url($update['url']); ?>" class="button"><?php esc_html_e('Update plugin', 'msv-magic-link-auth'); ?></a>
                    <?php else: ?>
                        <button type="button" class="button" disabled><?php esc_html_e('Update plugin', 'msv-magic-link-auth'); ?></button>
                    <?php endif; ?>
                </p>
                <p class="description"><?php echo esc_html($update['message']); ?></p>
            </div>

            <h2 class="nav-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e('Settings sections', 'msv-magic-link-auth'); ?>">
                <button type="button" class="nav-tab<?php echo $initial_tab === 'setup' ? ' nav-tab-active' : ''; ?>" role="tab" id="msv-tab-btn-setup" aria-controls="msv-tab-setup" aria-selected="<?php echo $initial_tab === 'setup' ? 'true' : 'false'; ?>" tabindex="<?php echo $initial_tab === 'setup' ? '0' : '-1'; ?>" data-msv-tab-target="setup"><?php esc_html_e('Setup', 'msv-magic-link-auth'); ?></button>
                <button type="button" class="nav-tab<?php echo $initial_tab === 'email' ? ' nav-tab-active' : ''; ?>" role="tab" id="msv-tab-btn-email" aria-controls="msv-tab-email" aria-selected="<?php echo $initial_tab === 'email' ? 'true' : 'false'; ?>" tabindex="<?php echo $initial_tab === 'email' ? '0' : '-1'; ?>" data-msv-tab-target="email"><?php esc_html_e('Email & Blocklist', 'msv-magic-link-auth'); ?></button>
                <button type="button" class="nav-tab<?php echo $initial_tab === 'messaging' ? ' nav-tab-active' : ''; ?>" role="tab" id="msv-tab-btn-messaging" aria-controls="msv-tab-messaging" aria-selected="<?php echo $initial_tab === 'messaging' ? 'true' : 'false'; ?>" tabindex="<?php echo $initial_tab === 'messaging' ? '0' : '-1'; ?>" data-msv-tab-target="messaging"><?php esc_html_e('Messaging', 'msv-magic-link-auth'); ?></button>
                <button type="button" class="nav-tab<?php echo $initial_tab === 'maintenance' ? ' nav-tab-active' : ''; ?>" role="tab" id="msv-tab-btn-maintenance" aria-controls="msv-tab-maintenance" aria-selected="<?php echo $initial_tab === 'maintenance' ? 'true' : 'false'; ?>" tabindex="<?php echo $initial_tab === 'maintenance' ? '0' : '-1'; ?>" data-msv-tab-target="maintenance"><?php esc_html_e('Maintenance', 'msv-magic-link-auth'); ?></button>
                <button type="button" class="nav-tab<?php echo $initial_tab === 'log' ? ' nav-tab-active' : ''; ?>" role="tab" id="msv-tab-btn-log" aria-controls="msv-tab-log" aria-selected="<?php echo $initial_tab === 'log' ? 'true' : 'false'; ?>" tabindex="<?php echo $initial_tab === 'log' ? '0' : '-1'; ?>" data-msv-tab-target="log"><?php esc_html_e('Log', 'msv-magic-link-auth'); ?></button>
            </h2>

            <form method="post" id="msv-settings-form">
                <?php wp_nonce_field(self::SETTINGS_NONCE_ACTION, 'msv_magic_settings_nonce'); ?>
                <input type="hidden" name="msv_active_tab" id="msv_active_tab" value="<?php echo esc_attr($initial_tab); ?>">

                <div class="msv-tab-panel" data-msv-tab="setup" id="msv-tab-setup" role="tabpanel" aria-labelledby="msv-tab-btn-setup" tabindex="0" <?php echo $initial_tab !== 'setup' ? 'hidden' : ''; ?>>
                    <h2><?php esc_html_e('Paths and limitations', 'msv-magic-link-auth'); ?></h2>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="request_page_id"><?php esc_html_e('Request page', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <?php echo $this->render_page_dropdown('request_page_id', $request_state['mode'], $request_state['page_id'], false); ?>
                                <input type="text" id="request_page_custom" name="request_page_custom" class="regular-text" placeholder="/example-path" value="<?php echo esc_attr($request_state['custom']); ?>" <?php echo $request_state['mode'] !== 'custom' ? 'style="display:none;"' : ''; ?>>
                                <p class="description"><?php esc_html_e('The page where visitors request a magic link.', 'msv-magic-link-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="confirm_page_id"><?php esc_html_e('Confirmation page', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <?php echo $this->render_page_dropdown('confirm_page_id', $confirm_state['mode'], $confirm_state['page_id'], true); ?>
                                <input type="text" id="confirm_page_custom" name="confirm_page_custom" class="regular-text" placeholder="/example-path" value="<?php echo esc_attr($confirm_state['custom']); ?>" <?php echo $confirm_state['mode'] !== 'custom' ? 'style="display:none;"' : ''; ?>>
                                <p class="description"><?php esc_html_e('Where the emailed magic link itself points to.', 'msv-magic-link-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="vote_page_id"><?php esc_html_e('Protected page', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <?php echo $this->render_page_dropdown('vote_page_id', $vote_state['mode'], $vote_state['page_id'], false); ?>
                                <input type="text" id="vote_page_custom" name="vote_page_custom" class="regular-text" placeholder="/example-path" value="<?php echo esc_attr($vote_state['custom']); ?>" <?php echo $vote_state['mode'] !== 'custom' ? 'style="display:none;"' : ''; ?>>
                                <p class="description"><?php esc_html_e('The page that requires a valid magic-link session to access.', 'msv-magic-link-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="max_attempts_per_hour"><?php esc_html_e('Max attempts per hour (per IP)', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="number" min="1" id="max_attempts_per_hour" name="max_attempts_per_hour" value="<?php echo esc_attr((string) $settings['max_attempts_per_hour']); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="token_ttl_hours"><?php esc_html_e('Magic link expiry (hours)', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="number" min="1" id="token_ttl_hours" name="token_ttl_hours" <?php disabled(!empty($settings['dev_mode'])); ?> value="<?php echo esc_attr((string) round($settings['token_ttl'] / HOUR_IN_SECONDS)); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="dev_mode"><?php esc_html_e('Development mode', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <label>
                                    <input type="checkbox" id="dev_mode" name="dev_mode" value="1" <?php checked(!empty($settings['dev_mode'])); ?>>
                                    <?php esc_html_e('Force magic link expiry to a fixed number of minutes, ignoring the hours setting above (for testing only)', 'msv-magic-link-auth'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="dev_mode_minutes"><?php esc_html_e('Development mode expiry (minutes)', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="number" min="1" id="dev_mode_minutes" name="dev_mode_minutes" <?php disabled(empty($settings['dev_mode'])); ?> value="<?php echo esc_attr((string) max(1, absint($settings['dev_mode_minutes']))); ?>"></td>
                        </tr>
                    </table>

                    <hr>
                    <h2><?php esc_html_e('Cloudflare Turnstile', 'msv-magic-link-auth'); ?></h2>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="turnstile_enabled"><?php esc_html_e('Enable Turnstile', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <label>
                                    <input type="checkbox" id="turnstile_enabled" name="turnstile_enabled" value="1" <?php checked(!empty($settings['turnstile_enabled'])); ?>>
                                    <?php esc_html_e('Verify Cloudflare Turnstile ourselves (leave off if another plugin or service already verifies it before this runs)', 'msv-magic-link-auth'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="site_key"><?php esc_html_e('Turnstile site key', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="text" id="site_key" name="site_key" class="regular-text" <?php disabled(empty($settings['turnstile_enabled'])); ?> value="<?php echo esc_attr($settings['site_key']); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="secret_key"><?php esc_html_e('Turnstile secret key', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="password" autocomplete="off" id="secret_key" name="secret_key" class="regular-text" <?php disabled(empty($settings['turnstile_enabled'])); ?> value="<?php echo esc_attr($settings['secret_key']); ?>"></td>
                        </tr>
                    </table>
                </div>

                <div class="msv-tab-panel" data-msv-tab="email" id="msv-tab-email" role="tabpanel" aria-labelledby="msv-tab-btn-email" tabindex="0" <?php echo $initial_tab !== 'email' ? 'hidden' : ''; ?>>
                    <h2><?php esc_html_e('Email setup', 'msv-magic-link-auth'); ?></h2>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="email_from_name"><?php esc_html_e('Email "from" name', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="text" id="email_from_name" name="email_from_name" class="regular-text" value="<?php echo esc_attr($settings['email_from_name']); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="email_subject"><?php esc_html_e('Email subject', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="text" id="email_subject" name="email_subject" class="regular-text" value="<?php echo esc_attr($settings['email_subject']); ?>"></td>
                        </tr>
                    </table>

                    <hr>
                    <h2><?php esc_html_e('Disposable email blocklist', 'msv-magic-link-auth'); ?></h2>
                    <p class="description">
                        <?php esc_html_e('Blocks known throwaway email services (e.g. Mailinator, temp-mail) from requesting a magic link, so one person can\'t register multiple accounts using disposable inboxes.', 'msv-magic-link-auth'); ?>
                        <?php esc_html_e('The plugin ships with a snapshot of a public blocklist. New disposable services appear constantly, so refresh this list shortly before you need it most accurate — no developer needed, just click the button below.', 'msv-magic-link-auth'); ?>
                    </p>
                    <p>
                        <?php if (is_array($disposable_status) && !empty($disposable_status['count'])): ?>
                            <?php
                            printf(
                                /* translators: 1: number of domains, 2: date/time last refreshed */
                                esc_html__('%1$s domains loaded — last refreshed %2$s.', 'msv-magic-link-auth'),
                                '<strong>' . esc_html((string) $disposable_status['count']) . '</strong>',
                                esc_html(wp_date('Y-m-d H:i', (int) ($disposable_status['refreshed'] ?? 0)))
                            );
                            ?>
                        <?php else: ?>
                            <?php esc_html_e('Using the snapshot bundled with the plugin (never refreshed since install).', 'msv-magic-link-auth'); ?>
                        <?php endif; ?>
                    </p>
                    <p>
                        <?php submit_button(__('Refresh list now', 'msv-magic-link-auth'), 'secondary', 'msv_magic_refresh_disposable', false, ['form' => 'msv-settings-form']); ?>
                    </p>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="custom_disposable_domains"><?php esc_html_e('Additional domains to block', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <textarea id="custom_disposable_domains" name="custom_disposable_domains" rows="4" class="large-text" placeholder="one-domain-per-line.com"><?php echo esc_textarea($settings['custom_disposable_domains']); ?></textarea>
                                <p class="description"><?php esc_html_e('Add domains you spot in the log (e.g. a rotating temp-mail domain) that aren\'t on the public list yet.', 'msv-magic-link-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="disposable_allowlist"><?php esc_html_e('Never block these domains', 'msv-magic-link-auth'); ?></label></th>
                            <td>
                                <textarea id="disposable_allowlist" name="disposable_allowlist" rows="4" class="large-text" placeholder="one-domain-per-line.com"><?php echo esc_textarea($settings['disposable_allowlist']); ?></textarea>
                                <p class="description"><?php esc_html_e('Use this if a legitimate domain ever gets wrongly blocked.', 'msv-magic-link-auth'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div class="msv-tab-panel" data-msv-tab="messaging" id="msv-tab-messaging" role="tabpanel" aria-labelledby="msv-tab-btn-messaging" tabindex="0" <?php echo $initial_tab !== 'messaging' ? 'hidden' : ''; ?>>
                    <h2><?php esc_html_e('Messages', 'msv-magic-link-auth'); ?></h2>
                    <p class="description"><?php esc_html_e('Shown to visitors as a dismissible message in the bottom-right corner of the request page.', 'msv-magic-link-auth'); ?></p>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="msg_sent"><?php esc_html_e('Link sent', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_sent" name="msg_sent" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_sent']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_invalid"><?php esc_html_e('Link invalid / expired / already used', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_invalid" name="msg_invalid" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_invalid']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_rate_limited"><?php esc_html_e('Too many attempts', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_rate_limited" name="msg_rate_limited" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_rate_limited']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_captcha_failed"><?php esc_html_e('Turnstile verification failed', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_captcha_failed" name="msg_captcha_failed" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_captcha_failed']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_email_required"><?php esc_html_e('Invalid/missing email', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_email_required" name="msg_email_required" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_email_required']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_confirm"><?php esc_html_e('Confirm-page prompt', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_confirm" name="msg_confirm" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_confirm']); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="msg_disposable"><?php esc_html_e('Disposable email rejected', 'msv-magic-link-auth'); ?></label></th>
                            <td><textarea id="msg_disposable" name="msg_disposable" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_disposable']); ?></textarea></td>
                        </tr>
                    </table>
                </div>

                <div class="msv-tab-panel" data-msv-tab="maintenance" id="msv-tab-maintenance" role="tabpanel" aria-labelledby="msv-tab-btn-maintenance" tabindex="0" <?php echo $initial_tab !== 'maintenance' ? 'hidden' : ''; ?>>
                    <h2><?php esc_html_e('TotalPoll voter IP cleanup', 'msv-magic-link-auth'); ?></h2>
                    <p class="description">
                        <?php esc_html_e('TotalPoll Pro logs each voter\'s IP address alongside every vote. This clears just the IP address from that log after voting closes. Vote counts and results are stored in a completely separate table with no personal data and are never affected.', 'msv-magic-link-auth'); ?>
                    </p>
                    <?php
                    $totalpoll_table = $this->get_totalpoll_log_table($settings['totalpoll_table_suffix'], $settings['totalpoll_ip_column']);
                    ?>
                    <p>
                        <?php if ($totalpoll_table !== null): ?>
                            <?php
                            printf(
                                /* translators: 1: database table name, 2: number of rows currently storing an IP address */
                                esc_html__('Detected table %1$s — %2$d entries currently store an IP address.', 'msv-magic-link-auth'),
                                '<code>' . esc_html($totalpoll_table) . '</code>',
                                (int) $this->count_totalpoll_ips($totalpoll_table, $settings['totalpoll_ip_column'])
                            );
                            ?>
                        <?php else: ?>
                            <?php esc_html_e('No matching table/column found - TotalPoll Pro may not be installed, or uses a different table/column name. The button below is disabled until a match is found.', 'msv-magic-link-auth'); ?>
                        <?php endif; ?>
                    </p>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="totalpoll_table_suffix"><?php esc_html_e('TotalPoll log table (without your site\'s table prefix)', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="text" id="totalpoll_table_suffix" name="totalpoll_table_suffix" class="regular-text" value="<?php echo esc_attr($settings['totalpoll_table_suffix']); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="totalpoll_ip_column"><?php esc_html_e('IP column name', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="text" id="totalpoll_ip_column" name="totalpoll_ip_column" class="regular-text" value="<?php echo esc_attr($settings['totalpoll_ip_column']); ?>"></td>
                        </tr>
                    </table>
                    <p>
                        <button
                            type="submit"
                            name="msv_magic_check_totalpoll"
                            value="1"
                            form="msv-settings-form"
                            class="button"
                        ><?php esc_html_e('Run checks now', 'msv-magic-link-auth'); ?></button>
                        <button
                            type="submit"
                            name="msv_magic_clear_totalpoll_ips"
                            value="1"
                            form="msv-settings-form"
                            class="button"
                            <?php echo $totalpoll_table === null ? 'disabled' : ''; ?>
                            onclick="return confirm(<?php echo esc_attr(wp_json_encode(__('This will permanently clear all voter IP addresses from the TotalPoll log. This cannot be undone. Only do this after voting has fully closed. Continue?', 'msv-magic-link-auth'))); ?>);"
                        ><?php esc_html_e('Clear TotalPoll voter IPs now', 'msv-magic-link-auth'); ?></button>
                    </p>

                    <h3><?php esc_html_e('Automatic purge schedule', 'msv-magic-link-auth'); ?></h3>
                    <?php
                    echo $this->render_schedule_fieldset(
                        'totalpoll',
                        $this->get_schedule(self::TOTALPOLL_SCHEDULE_OPTION_KEY),
                        'msv_magic_save_totalpoll_schedule',
                        __('When to purge automatically', 'msv-magic-link-auth')
                    );
                    ?>

                    <hr>
                    <h2><?php esc_html_e('Delete all voters', 'msv-magic-link-auth'); ?></h2>
                    <p class="description">
                        <?php esc_html_e('Permanently deletes WordPress accounts. Choose which accounts count as "voters" below, then use the manual button or an automatic schedule to remove them once you no longer need their accounts (for example, after voting has fully closed).', 'msv-magic-link-auth'); ?>
                    </p>
                    <?php $voter_role_count = $this->count_voters('role'); $voter_tag_count = $this->count_voters('tag'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><?php esc_html_e('Which accounts to delete', 'msv-magic-link-auth'); ?></th>
                            <td>
                                <label>
                                    <input type="radio" name="voter_delete_match_mode" value="role" <?php checked($settings['voter_delete_match_mode'], 'role'); ?>>
                                    <?php
                                    printf(
                                        /* translators: %d: number of matching accounts */
                                        esc_html__('Every account whose only role is Subscriber (%d account(s)). Never touches administrators, editors, or any other multi-role account. Includes accounts that already existed before this feature was added.', 'msv-magic-link-auth'),
                                        (int) $voter_role_count
                                    );
                                    ?>
                                </label><br>
                                <label>
                                    <input type="radio" name="voter_delete_match_mode" value="tag" <?php checked($settings['voter_delete_match_mode'], 'tag'); ?>>
                                    <?php
                                    printf(
                                        /* translators: %d: number of matching accounts */
                                        esc_html__('Only accounts this plugin itself created (%d account(s)). Safer on a site that also uses the Subscriber role for other members, but cannot include accounts created before this feature was added.', 'msv-magic-link-auth'),
                                        (int) $voter_tag_count
                                    );
                                    ?>
                                </label>
                            </td>
                        </tr>
                    </table>
                    <?php
                    $voter_confirm_role = sprintf(
                        /* translators: %d: number of matching accounts */
                        __('This will permanently delete %d account(s) matching "every Subscriber-only account". This cannot be undone. Continue?', 'msv-magic-link-auth'),
                        $voter_role_count
                    );
                    $voter_confirm_tag = sprintf(
                        /* translators: %d: number of matching accounts */
                        __('This will permanently delete %d account(s) matching "accounts created by this plugin". This cannot be undone. Continue?', 'msv-magic-link-auth'),
                        $voter_tag_count
                    );
                    ?>
                    <p>
                        <button
                            type="submit"
                            name="msv_magic_delete_voters_now"
                            value="1"
                            form="msv-settings-form"
                            class="button"
                            id="msv-delete-voters-btn"
                            data-confirm-role="<?php echo esc_attr($voter_confirm_role); ?>"
                            data-confirm-tag="<?php echo esc_attr($voter_confirm_tag); ?>"
                            <?php echo ($settings['voter_delete_match_mode'] === 'tag' ? $voter_tag_count : $voter_role_count) === 0 ? 'disabled' : ''; ?>
                        ><?php esc_html_e('Delete all voters now', 'msv-magic-link-auth'); ?></button>
                    </p>

                    <h3><?php esc_html_e('Automatic deletion schedule', 'msv-magic-link-auth'); ?></h3>
                    <?php
                    echo $this->render_schedule_fieldset(
                        'voter_delete',
                        $this->get_schedule(self::VOTER_DELETE_SCHEDULE_OPTION_KEY),
                        'msv_magic_save_voter_delete_schedule',
                        __('When to delete automatically', 'msv-magic-link-auth')
                    );
                    ?>
                </div>

                <div class="msv-tab-panel" data-msv-tab="log" id="msv-tab-log" role="tabpanel" aria-labelledby="msv-tab-btn-log" tabindex="0" <?php echo $initial_tab !== 'log' ? 'hidden' : ''; ?>>
                    <h2><?php esc_html_e('Log retention', 'msv-magic-link-auth'); ?></h2>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="log_retention_days"><?php esc_html_e('Keep log entries for (days)', 'msv-magic-link-auth'); ?></label></th>
                            <td><input type="number" min="1" id="log_retention_days" name="log_retention_days" value="<?php echo esc_attr((string) max(1, absint($settings['log_retention_days']))); ?>"></td>
                        </tr>
                    </table>
                </div>
            </form>

            <div class="msv-tab-panel" data-msv-tab="log" id="msv-tab-log-recent" <?php echo $initial_tab !== 'log' ? 'hidden' : ''; ?>>
                <hr>
                <h2><?php esc_html_e('Recent log', 'msv-magic-link-auth'); ?></h2>
                <?php if (empty($log)): ?>
                    <p><?php esc_html_e('No log entries yet.', 'msv-magic-link-auth'); ?></p>
                <?php else: ?>
                    <table class="widefat striped">
                        <thead>
                            <tr>
                                <th style="width:160px;"><?php esc_html_e('Time', 'msv-magic-link-auth'); ?></th>
                                <th style="width:80px;"><?php esc_html_e('Level', 'msv-magic-link-auth'); ?></th>
                                <th><?php esc_html_e('Message', 'msv-magic-link-auth'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($log as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time'] ?? ''); ?></td>
                                <td><?php echo esc_html($entry['level'] ?? ''); ?></td>
                                <td><?php echo esc_html($entry['message'] ?? ''); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <form method="post" style="margin-top:12px;">
                        <?php wp_nonce_field(self::SETTINGS_NONCE_ACTION, 'msv_magic_settings_nonce'); ?>
                        <input type="hidden" name="msv_magic_clear_log" value="1">
                        <?php submit_button(__('Clear log', 'msv-magic-link-auth'), 'delete', 'submit', false); ?>
                    </form>
                <?php endif; ?>
            </div>

            <style>
                .msv-sticky-header {
                    position: sticky;
                    top: 0;
                    z-index: 30;
                    background: #f0f0f1;
                    padding-top: 10px;
                    border-bottom: 1px solid #dcdcde;
                }
                .msv-has-adminbar .msv-sticky-header { top: 32px; }
                @media screen and (max-width: 782px) {
                    .msv-has-adminbar .msv-sticky-header { top: 46px; }
                }
            </style>
            <script>
            (function () {
                var TABS = ['setup', 'email', 'messaging', 'maintenance', 'log'];

                function activateTab(tab, skipHistory) {
                    if (TABS.indexOf(tab) === -1) { tab = TABS[0]; }
                    document.querySelectorAll('[data-msv-tab-target]').forEach(function (btn) {
                        var on = btn.getAttribute('data-msv-tab-target') === tab;
                        btn.classList.toggle('nav-tab-active', on);
                        btn.setAttribute('aria-selected', on ? 'true' : 'false');
                        btn.tabIndex = on ? 0 : -1;
                    });
                    document.querySelectorAll('[data-msv-tab]').forEach(function (panel) {
                        panel.hidden = panel.getAttribute('data-msv-tab') !== tab;
                    });
                    var hiddenField = document.getElementById('msv_active_tab');
                    if (hiddenField) { hiddenField.value = tab; }
                    if (!skipHistory && window.history && history.replaceState) {
                        history.replaceState(null, '', '#tab=' + tab);
                    }
                }

                function syncDevMode() {
                    var devMode = document.getElementById('dev_mode');
                    var hours = document.getElementById('token_ttl_hours');
                    var minutes = document.getElementById('dev_mode_minutes');
                    if (!devMode || !hours || !minutes) { return; }
                    hours.disabled = devMode.checked;
                    minutes.disabled = !devMode.checked;
                }
                function syncTurnstile() {
                    var enabled = document.getElementById('turnstile_enabled');
                    var siteKey = document.getElementById('site_key');
                    var secretKey = document.getElementById('secret_key');
                    if (!enabled || !siteKey || !secretKey) { return; }
                    siteKey.disabled = !enabled.checked;
                    secretKey.disabled = !enabled.checked;
                }
                function syncPagePicker(selectId, inputId) {
                    var select = document.getElementById(selectId), input = document.getElementById(inputId);
                    if (!select || !input) { return; }
                    input.style.display = select.value === '0' ? '' : 'none';
                }

                function syncScheduleFieldset(fieldset) {
                    var checked = fieldset.querySelector('.msv-schedule-mode-radio:checked');
                    var mode = checked ? checked.value : 'off';
                    fieldset.querySelectorAll('.msv-schedule-group').forEach(function (group) {
                        group.hidden = group.getAttribute('data-schedule-group') !== mode;
                    });
                }

                function syncDeleteVotersButton() {
                    var btn = document.getElementById('msv-delete-voters-btn');
                    var checked = document.querySelector('input[name="voter_delete_match_mode"]:checked');
                    if (!btn || !checked) { return; }
                    btn.setAttribute('data-confirm-active', btn.getAttribute('data-confirm-' + checked.value) || '');
                }

                document.addEventListener('DOMContentLoaded', function () {
                    var devMode = document.getElementById('dev_mode');
                    var turnstile = document.getElementById('turnstile_enabled');
                    if (devMode) { devMode.addEventListener('change', syncDevMode); }
                    if (turnstile) { turnstile.addEventListener('change', syncTurnstile); }
                    syncDevMode();
                    syncTurnstile();

                    [['request_page_id', 'request_page_custom'], ['confirm_page_id', 'confirm_page_custom'], ['vote_page_id', 'vote_page_custom']].forEach(function (pair) {
                        var select = document.getElementById(pair[0]);
                        if (select) {
                            select.addEventListener('change', function () { syncPagePicker(pair[0], pair[1]); });
                        }
                        syncPagePicker(pair[0], pair[1]);
                    });

                    document.querySelectorAll('.msv-schedule-fieldset').forEach(function (fieldset) {
                        fieldset.querySelectorAll('.msv-schedule-mode-radio').forEach(function (radio) {
                            radio.addEventListener('change', function () { syncScheduleFieldset(fieldset); });
                        });
                        syncScheduleFieldset(fieldset);
                    });

                    document.querySelectorAll('input[name="voter_delete_match_mode"]').forEach(function (radio) {
                        radio.addEventListener('change', syncDeleteVotersButton);
                    });
                    syncDeleteVotersButton();
                    var deleteVotersBtn = document.getElementById('msv-delete-voters-btn');
                    if (deleteVotersBtn) {
                        deleteVotersBtn.addEventListener('click', function (e) {
                            var message = deleteVotersBtn.getAttribute('data-confirm-active');
                            if (message && !confirm(message)) {
                                e.preventDefault();
                            }
                        });
                    }

                    document.querySelectorAll('[data-msv-tab-target]').forEach(function (btn) {
                        btn.addEventListener('click', function () { activateTab(btn.getAttribute('data-msv-tab-target')); });
                        btn.addEventListener('keydown', function (e) {
                            var buttons = Array.prototype.slice.call(document.querySelectorAll('[data-msv-tab-target]'));
                            var index = buttons.indexOf(btn);
                            if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                                var next = e.key === 'ArrowRight' ? (index + 1) % buttons.length : (index - 1 + buttons.length) % buttons.length;
                                buttons[next].focus();
                                activateTab(buttons[next].getAttribute('data-msv-tab-target'));
                                e.preventDefault();
                            }
                        });
                    });

                    if (window.location.hash.indexOf('tab=') !== -1) {
                        activateTab(window.location.hash.split('tab=')[1], true);
                    }
                });
            })();
            </script>
        </div>
        <?php
    }
}

/**
 * Declares MSV_Magic_Link_Elementor_Form_Action the first time it's needed.
 * Kept as a plain function (not a class method) because PHP does not allow
 * class declarations nested inside a method body, only inside a function.
 */
function msv_magic_link_declare_elementor_action(): void {
    if (class_exists('MSV_Magic_Link_Elementor_Form_Action')) {
        return;
    }

    class MSV_Magic_Link_Elementor_Form_Action extends \ElementorPro\Modules\Forms\Classes\Action_Base {
        public function get_name() {
            return 'msv_magic_link';
        }

        public function get_label() {
            return __('Magic Link Auth', 'msv-magic-link-auth');
        }

        public function run($record, $ajax_handler) {
            MSV_Magic_Link_Auth::instance()->handle_elementor_form_submission($record, $ajax_handler);
        }

        public function register_fields($widget) {}

        public function register_settings_section($widget) {}

        public function on_export($element) {}
    }
}

new MSV_Magic_Link_Auth();
