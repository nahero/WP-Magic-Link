<?php
/**
 * Plugin Name: WP Magic Link Auth
 * Description: Custom magic-link auth flow for MSV voting with Cloudflare Turnstile, rate limiting, and protected vote page. Supports both the [msv_magic_link_form] shortcode and an Elementor Pro form action.
 * Author: igor@igibits.com
 * Version: 0.6.0
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

    private static ?self $instance = null;

    public function __construct() {
        self::$instance = $this;

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
    }

    public static function instance(): self {
        return self::$instance;
    }

    public static function defaults(): array {
        return [
            'site_key' => '',
            'secret_key' => '',
            'request_page_path' => '/accueil-votez',
            'confirm_page_path' => '',
            'vote_page_path' => '/votez',
            'future_request_page_path' => '/',
            'token_ttl' => DAY_IN_SECONDS,
            'max_attempts_per_hour' => 3,
            'email_from_name' => get_bloginfo('name'),
            'email_subject' => 'Votre lien de vote',
            'dev_mode' => false,
            'dev_mode_minutes' => 10,
            'turnstile_enabled' => false,
            'msg_sent' => 'Vérifiez votre boîte mail : nous venons de vous envoyer votre lien de vote.',
            'msg_invalid' => "Ce lien n'est plus valide. Il a peut-être déjà été utilisé ou a expiré. Merci de demander un nouveau lien ci-dessous.",
            'msg_rate_limited' => 'Trop de tentatives depuis cette adresse. Merci de réessayer plus tard.',
            'msg_captcha_failed' => 'La vérification de sécurité a échoué. Merci de réessayer.',
            'msg_email_required' => 'Merci de saisir une adresse email valide.',
            'msg_confirm' => 'Cliquez sur le bouton ci-dessous pour confirmer votre identité et accéder au vote.',
            'msg_disposable' => "Les adresses e-mail jetables ne sont pas autorisées. Merci d'utiliser une adresse personnelle.",
            'custom_disposable_domains' => '',
            'disposable_allowlist' => '',
            'log_retention_days' => 3,
        ];
    }

    public static function settings(): array {
        $settings = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());

        if (!empty($settings['dev_mode'])) {
            $settings['token_ttl'] = max(1, (int) $settings['dev_mode_minutes']) * MINUTE_IN_SECONDS;
        }

        return $settings;
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

    public function render_form_shortcode(): string {
        $settings = self::settings();
        $message = '';
        $error = '';

        if (isset($_GET['msv_magic_status'])) {
            $status = sanitize_key(wp_unslash($_GET['msv_magic_status']));
            if ($status === 'sent') {
                $message = 'Check your email for your magic link.';
            } elseif ($status === 'invalid') {
                $error = 'This magic link is invalid or has expired.';
            } elseif ($status === 'rate_limited') {
                $error = 'Too many attempts from this IP. Please wait and try again later.';
            } elseif ($status === 'captcha_failed') {
                $error = 'Turnstile verification failed. Please try again.';
            } elseif ($status === 'email_required') {
                $error = 'Please enter a valid email address.';
            } elseif ($status === 'disposable') {
                $error = 'Disposable email addresses are not allowed.';
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
                    <label for="msv_magiclinkemail" class="screen-reader-text">Email</label>
                    <input type="email" id="msv_magiclinkemail" name="magiclinkemail" required autocomplete="email" placeholder="Email" />
                </p>
                <?php if (!empty($settings['turnstile_enabled'])): ?>
                    <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($settings['site_key']); ?>" data-theme="auto"></div>
                <?php endif; ?>
                <p>
                    <button type="submit">Recevoir le lien magique</button>
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
            wp_die('Invalid request.', 403);
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
     * "MSV Magic Link" action registered in register_elementor_form_action().
     * Elementor's own AJAX handler never reaches handle_form_submission()
     * above (different POST shape/route), so this is a separate entry point
     * into the same rate-limit/turnstile/issue_magic_link logic.
     *
     * @param \ElementorPro\Modules\Forms\Classes\Form_Record $record
     * @param \ElementorPro\Modules\Forms\Classes\Ajax_Handler $ajax_handler
     */
    public function handle_elementor_form_submission($record, $ajax_handler): void {
        $fields = $record->get('fields');
        $email = isset($fields['magiclinkemail']['value']) ? sanitize_email($fields['magiclinkemail']['value']) : '';

        if (!$email || !is_email($email)) {
            $ajax_handler->add_error_message('Please enter a valid email address.');
            return;
        }
        $email = $this->normalize_email($email);

        if ($this->is_disposable_email($email)) {
            $this->log_event('warning', 'Blocked disposable email domain: ' . substr($email, strrpos($email, '@') + 1));
            $ajax_handler->add_error_message(self::settings()['msg_disposable']);
            return;
        }

        if ($this->is_rate_limited()) {
            $ajax_handler->add_error_message('Too many attempts from this IP. Please wait and try again later.');
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
     * Registers the "MSV Magic Link" action so it can be attached under an
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
                        esc_html('MSV Magic Link Auth: "MSV Magic Link" Elementor action was NOT registered. ' . $base_class . ' requires a method this plugin does not implement: ' . $missing . '().'),
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
            wp_die('Invalid request.', 403);
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
            button.textContent = 'Accéder au vote';

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
        $logo_url = plugins_url('assets/logo.png', __FILE__);

        $message = '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>' . esc_html($subject) . '</title></head>'
            . '<body style="margin:0;padding:0;background-color:#080e10;font-family:Arial,Helvetica,sans-serif;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#080e10;margin:0;padding:0;"><tr><td align="center" style="padding:48px 20px;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;">'
            . '<tr><td align="left" style="padding:0 0 28px;"><img src="' . esc_url($logo_url) . '" alt="' . esc_attr(get_bloginfo('name')) . '" width="200" style="display:block;width:200px;height:auto;"></td></tr>'
            . '<tr><td style="background-color:#2e3335;border:4px solid #d4a95e;border-radius:32px 0px 32px 0px;padding:44px 40px;box-shadow:0 2px 24px rgba(0,0,0,0.8);">'
            . '<h1 style="margin:0 0 20px;font-size:32px;text-transform:uppercase;line-height:1.3;color:#d4a95e;font-weight:400;font-family:Arial,Helvetica,sans-serif;">Votre lien de vote</h1>'
            . '<p style="margin:0 0 16px;font-size:16px;line-height:1.6;color:#ffffff;">Bonjour,</p>'
            . '<p style="margin:0 0 32px;font-size:16px;line-height:1.6;color:#ffffff;">Cliquez sur le bouton ci-dessous pour accéder au vote. Ce lien est valable 24 heures et ne peut être utilisé qu\'une seule fois.</p>'
            . '<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:999px;background-color:#d4a95e;">'
            . '<a href="' . esc_url($magic_url) . '" style="display:inline-block;padding:16px 34px;font-size:16px;font-weight:700;color:#080e10;text-decoration:none;border-radius:999px;font-family:Arial,Helvetica,sans-serif;">Accéder au vote</a>'
            . '</td></tr></table>'
            . '<p style="margin:36px 0 8px;font-size:14px;line-height:1.6;color:#a1a4a5;">Si le bouton ne fonctionne pas, utilisez ce lien :</p>'
            . '<p style="margin:0 0 32px;font-size:14px;line-height:1.6;word-break:break-all;"><a href="' . esc_url($magic_url) . '" style="color:rgba(161,164,165,0.6);text-decoration:underline;">' . esc_html($magic_url) . '</a></p>'
            . '<hr style="border:none;border-top:1px solid rgba(161,164,165,0.25);margin:0 0 20px;">'
            . '<p style="margin:0;font-size:12px;line-height:1.6;color:#a1a4a5;">Si vous n\'avez pas demandé ce lien, ignorez cet e-mail.</p>'
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
        $info->name = 'WP Magic Link Auth';
        $info->slug = dirname(plugin_basename(__FILE__));
        $info->version = $release['tag_name'];
        $info->author = '<a href="mailto:igor@igibits.com">igor@igibits.com</a>';
        $info->homepage = $release['html_url'];
        $info->requires_php = '8.4';
        $info->download_link = $release['package_url'];
        $info->sections = [
            'description' => 'Passwordless magic-link auth for the voting site.',
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
            'WP Magic Link Auth',
            'WP Magic Link Auth',
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

    public function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $notice = '';
        $error_notice = '';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!isset($_POST['msv_magic_settings_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['msv_magic_settings_nonce'])), self::SETTINGS_NONCE_ACTION)) {
                wp_die('Invalid request.', 403);
            }

            if (isset($_POST['msv_magic_clear_log'])) {
                delete_option(self::LOG_OPTION_KEY);
                $notice = 'Log cleared.';
            } elseif (isset($_POST['msv_magic_refresh_disposable'])) {
                $result = $this->refresh_disposable_list_from_source();
                if (is_wp_error($result)) {
                    $error_notice = 'Could not refresh the list: ' . $result->get_error_message() . ' The current list was left unchanged.';
                } else {
                    $notice = 'Disposable-domain list refreshed: ' . (int) $result['count'] . ' domains.';
                }
            } else {
                // Empty means "not configured, fall back to request_page_path" -
                // distinct from sanitize_path()'s own empty-input behavior,
                // which would turn it into "/" (the home page).
                $confirm_page_path_raw = trim(sanitize_text_field(wp_unslash($_POST['confirm_page_path'] ?? '')));

                update_option(self::OPTION_KEY, [
                    'site_key' => sanitize_text_field(wp_unslash($_POST['site_key'] ?? '')),
                    'secret_key' => sanitize_text_field(wp_unslash($_POST['secret_key'] ?? '')),
                    'request_page_path' => $this->sanitize_path(wp_unslash($_POST['request_page_path'] ?? '')),
                    'confirm_page_path' => $confirm_page_path_raw === '' ? '' : $this->sanitize_path($confirm_page_path_raw),
                    'vote_page_path' => $this->sanitize_path(wp_unslash($_POST['vote_page_path'] ?? '')),
                    'max_attempts_per_hour' => max(1, absint($_POST['max_attempts_per_hour'] ?? 3)),
                    'token_ttl' => max(1, absint($_POST['token_ttl_hours'] ?? 24)) * HOUR_IN_SECONDS,
                    'dev_mode' => isset($_POST['dev_mode']),
                    'dev_mode_minutes' => max(1, absint($_POST['dev_mode_minutes'] ?? 10)),
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
                ]);
                $notice = 'Settings saved.';
            }
        }

        // Deliberately NOT self::settings() here: that applies the dev-mode
        // minutes override to token_ttl, which would make this form display
        // (and, on save, persist) the wrong "expiry hours" value while dev
        // mode is on. This page always shows/edits the real stored config.
        $settings = wp_parse_args(get_option(self::OPTION_KEY, []), self::defaults());
        $log = get_option(self::LOG_OPTION_KEY, []);
        if (!is_array($log)) {
            $log = [];
        }
        $update = $this->get_update_status_for_display();
        ?>
        <div class="wrap">
            <h1><strong>WP Magic Link Auth</strong></h1>
            <p>Developed by igor@igibits.com</p>
            <?php if ($notice): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html($notice); ?></p></div>
            <?php endif; ?>
            <?php if ($error_notice): ?>
                <div class="notice notice-error is-dismissible"><p><?php echo esc_html($error_notice); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($settings['dev_mode'])): ?>
                <div class="notice notice-warning"><p><strong>Development mode is ON</strong> — magic links expire after <?php echo esc_html((string) max(1, absint($settings['dev_mode_minutes']))); ?> minute(s) regardless of the setting below. Turn this off before the real election.</p></div>
            <?php endif; ?>

            <form method="post">
                <?php wp_nonce_field(self::SETTINGS_NONCE_ACTION, 'msv_magic_settings_nonce'); ?>

                <p style="display:flex;gap:8px;align-items:center;">
                    <?php submit_button('Save settings', 'primary', 'submit', false); ?>
                    <?php if ($update['available']): ?>
                        <a href="<?php echo esc_url($update['url']); ?>" class="button">Update plugin</a>
                    <?php else: ?>
                        <button type="button" class="button" disabled>Update plugin</button>
                    <?php endif; ?>
                </p>
                <p class="description"><?php echo esc_html($update['message']); ?></p>
                <hr>

                <h2>Paths and limitations</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="request_page_path">Request page path</label></th>
                        <td><input type="text" id="request_page_path" name="request_page_path" class="regular-text" value="<?php echo esc_attr($settings['request_page_path']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="confirm_page_path">Vote confirmation page path</label></th>
                        <td>
                            <input type="text" id="confirm_page_path" name="confirm_page_path" class="regular-text" placeholder="<?php echo esc_attr($settings['request_page_path']); ?>" value="<?php echo esc_attr($settings['confirm_page_path']); ?>">
                            <p class="description">Where the emailed magic link itself points to. Leave blank to use the request page path above.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="vote_page_path">Vote page path</label></th>
                        <td><input type="text" id="vote_page_path" name="vote_page_path" class="regular-text" value="<?php echo esc_attr($settings['vote_page_path']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="max_attempts_per_hour">Max attempts per hour (per IP)</label></th>
                        <td><input type="number" min="1" id="max_attempts_per_hour" name="max_attempts_per_hour" value="<?php echo esc_attr((string) $settings['max_attempts_per_hour']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="token_ttl_hours">Magic link expiry (hours)</label></th>
                        <td><input type="number" min="1" id="token_ttl_hours" name="token_ttl_hours" <?php disabled(!empty($settings['dev_mode'])); ?> value="<?php echo esc_attr((string) round($settings['token_ttl'] / HOUR_IN_SECONDS)); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="dev_mode">Development mode</label></th>
                        <td>
                            <label>
                                <input type="checkbox" id="dev_mode" name="dev_mode" value="1" <?php checked(!empty($settings['dev_mode'])); ?>>
                                Force magic link expiry to a fixed number of minutes, ignoring the hours setting above (for testing only)
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="dev_mode_minutes">Development mode expiry (minutes)</label></th>
                        <td><input type="number" min="1" id="dev_mode_minutes" name="dev_mode_minutes" <?php disabled(empty($settings['dev_mode'])); ?> value="<?php echo esc_attr((string) max(1, absint($settings['dev_mode_minutes']))); ?>"></td>
                    </tr>
                </table>

                <h2>Email setup</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="email_from_name">Email "from" name</label></th>
                        <td><input type="text" id="email_from_name" name="email_from_name" class="regular-text" value="<?php echo esc_attr($settings['email_from_name']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="email_subject">Email subject</label></th>
                        <td><input type="text" id="email_subject" name="email_subject" class="regular-text" value="<?php echo esc_attr($settings['email_subject']); ?>"></td>
                    </tr>
                </table>

                <h2>Cloudflare Turnstile</h2>
                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row"><label for="turnstile_enabled">Enable Turnstile</label></th>
                            <td>
                                <label>
                                    <input type="checkbox" id="turnstile_enabled" name="turnstile_enabled" value="1" <?php checked(!empty($settings['turnstile_enabled'])); ?>>
                                    Verify Cloudflare Turnstile ourselves (leave off if another plugin already handles it on the live form)
                                </label>
                            </td>
                        </tr>
                    </tbody>
                    <tbody id="msv-turnstile-keys" <?php echo empty($settings['turnstile_enabled']) ? 'style="display:none;"' : ''; ?>>
                        <tr>
                            <th scope="row"><label for="site_key">Turnstile site key</label></th>
                            <td><input type="text" id="site_key" name="site_key" class="regular-text" value="<?php echo esc_attr($settings['site_key']); ?>"></td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="secret_key">Turnstile secret key</label></th>
                            <td><input type="password" autocomplete="off" id="secret_key" name="secret_key" class="regular-text" value="<?php echo esc_attr($settings['secret_key']); ?>"></td>
                        </tr>
                    </tbody>
                </table>

                <h2>Messages</h2>
                <p class="description">Shown to visitors as a dismissible message in the bottom-right corner of the request page.</p>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="msg_sent">Link sent</label></th>
                        <td><textarea id="msg_sent" name="msg_sent" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_sent']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_invalid">Link invalid / expired / already used</label></th>
                        <td><textarea id="msg_invalid" name="msg_invalid" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_invalid']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_rate_limited">Too many attempts</label></th>
                        <td><textarea id="msg_rate_limited" name="msg_rate_limited" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_rate_limited']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_captcha_failed">Turnstile verification failed</label></th>
                        <td><textarea id="msg_captcha_failed" name="msg_captcha_failed" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_captcha_failed']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_email_required">Invalid/missing email</label></th>
                        <td><textarea id="msg_email_required" name="msg_email_required" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_email_required']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_confirm">Confirm-page prompt</label></th>
                        <td><textarea id="msg_confirm" name="msg_confirm" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_confirm']); ?></textarea></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="msg_disposable">Disposable email rejected</label></th>
                        <td><textarea id="msg_disposable" name="msg_disposable" rows="2" class="large-text"><?php echo esc_textarea($settings['msg_disposable']); ?></textarea></td>
                    </tr>
                </table>

                <h2>Disposable email blocklist</h2>
                <p class="description">
                    Blocks known throwaway email services (Mailinator, temp-mail, etc.) from requesting a magic link, so one person can't vote multiple times using disposable inboxes.
                    The plugin ships with a snapshot of a public blocklist. New disposable services appear constantly, so <strong>refresh this list shortly before voting opens</strong> to get the most current version — you don't need the developer for this, just click the button below.
                </p>
                <?php $disposable_status = get_option(self::DISPOSABLE_OPTION_KEY, []); ?>
                <p>
                    <?php if (is_array($disposable_status) && !empty($disposable_status['count'])): ?>
                        <strong><?php echo esc_html((string) $disposable_status['count']); ?> domains loaded</strong> — last refreshed <?php echo esc_html(wp_date('Y-m-d H:i', (int) ($disposable_status['refreshed'] ?? 0))); ?>.
                    <?php else: ?>
                        Using the snapshot bundled with the plugin (never refreshed since install).
                    <?php endif; ?>
                </p>
                <p>
                    <?php submit_button('Refresh list now', 'secondary', 'msv_magic_refresh_disposable', false); ?>
                </p>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="custom_disposable_domains">Additional domains to block</label></th>
                        <td>
                            <textarea id="custom_disposable_domains" name="custom_disposable_domains" rows="4" class="large-text" placeholder="one-domain-per-line.com"><?php echo esc_textarea($settings['custom_disposable_domains']); ?></textarea>
                            <p class="description">Add domains you spot in the log (e.g. a rotating temp-mail domain) that aren't on the public list yet.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="disposable_allowlist">Never block these domains</label></th>
                        <td>
                            <textarea id="disposable_allowlist" name="disposable_allowlist" rows="4" class="large-text" placeholder="one-domain-per-line.com"><?php echo esc_textarea($settings['disposable_allowlist']); ?></textarea>
                            <p class="description">Use this if a legitimate domain ever gets wrongly blocked.</p>
                        </td>
                    </tr>
                </table>

                <h2>Log retention</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="log_retention_days">Keep log entries for (days)</label></th>
                        <td><input type="number" min="1" id="log_retention_days" name="log_retention_days" value="<?php echo esc_attr((string) max(1, absint($settings['log_retention_days']))); ?>"></td>
                    </tr>
                </table>
            </form>

            <script>
            (function () {
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
                    var keys = document.getElementById('msv-turnstile-keys');
                    if (!enabled || !keys) { return; }
                    keys.style.display = enabled.checked ? '' : 'none';
                }
                document.addEventListener('DOMContentLoaded', function () {
                    var devMode = document.getElementById('dev_mode');
                    var turnstile = document.getElementById('turnstile_enabled');
                    if (devMode) { devMode.addEventListener('change', syncDevMode); }
                    if (turnstile) { turnstile.addEventListener('change', syncTurnstile); }
                    syncDevMode();
                    syncTurnstile();
                });
            })();
            </script>

            <h2>Recent log</h2>
            <?php if (empty($log)): ?>
                <p>No log entries yet.</p>
            <?php else: ?>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th style="width:160px;">Time</th>
                            <th style="width:80px;">Level</th>
                            <th>Message</th>
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
                    <?php submit_button('Clear log', 'delete', 'submit', false); ?>
                </form>
            <?php endif; ?>
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
            return __('MSV Magic Link', 'msv-magic-link-auth');
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
