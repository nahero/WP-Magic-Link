=== WP Magic Link Auth ===
Contributors: igor@igibits.com
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 8.4
Stable tag: 0.9.3
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless magic-link authentication with rate limiting, an optional protected page, Cloudflare Turnstile support, and a disposable-email blocklist.

== Description ==

WP Magic Link Auth lets visitors sign in by email instead of a password: they enter their address, receive a single-use link, and clicking it confirms their identity and logs them in. No account creation form, no password to remember or leak.

Core features:

* **Passwordless login** — a WordPress `subscriber` account is created (or reused) automatically the first time someone requests a link.
* **Two-step confirm flow** — the emailed link only *peeks* at validity; the actual sign-in only happens when the visitor clicks a "Continue" button and submits a real form. This prevents corporate email security scanners (Microsoft Safe Links, Proofpoint, etc.) and chat-app link-preview bots from silently burning single-use links before the real recipient ever clicks them.
* **Optional protected page** — logged-out visitors are redirected away from a page you choose.
* **Rate limiting** — configurable max attempts per hour per IP address.
* **Disposable-email blocklist** — rejects known throwaway email domains (Mailinator, temp-mail, etc.) at request time, with a one-click "refresh from source" button so the blocklist can be kept current without a plugin update, plus admin-editable custom blocklist/allowlist entries.
* **Email-address normalization** — collapses `name+tag@gmail.com` and dotted Gmail variants to a single canonical account, closing a common multi-account trick.
* **Cloudflare Turnstile support** — optional, for when no other plugin already verifies it.
* **Works two ways** — a `[msv_magic_link_form]` shortcode, or an Elementor Pro form action ("Actions After Submit") for use inside an existing Elementor form.
* **Editable, translatable messages** — every visitor-facing message is editable from the settings screen and follows your site's language via standard WordPress translation files.
* **Built-in diagnostic log** — every issued/consumed/rejected link is logged with a non-reversible token fingerprint, requester IP, and user agent, pruned automatically by age.
* **TotalPoll voter IP cleanup** — if TotalPoll Pro is installed, a Maintenance-tab button clears voter IP addresses from its log table once voting has closed, without touching vote counts or results. The table/column are auto-detected (and can be overridden) so this works regardless of your site's table prefix, and a "Run checks now" button reports readiness before you rely on it.
* **Delete all voters** — permanently removes voter accounts, either every Subscriber-only account or just the accounts this plugin itself created, whichever you choose. Manual button or automatic schedule.
* **Scheduled maintenance** — both the TotalPoll IP cleanup and the delete-all-voters action can run manually, once at a chosen date/time, or repeating every N days between a start and end date, via WordPress's built-in cron.
* **Self-updating from GitHub** — once installed, updates appear in the normal WordPress "Update plugin" flow.

== Installation ==

1. Download the latest release zip from the GitHub repository's Releases page.
2. In wp-admin, go to **Plugins → Add New → Upload Plugin** and select the zip.
3. Activate the plugin.
4. Go to **Settings → WP Magic Link Auth** and configure the Setup tab: choose a request page (where visitors enter their email), a protected page (if any), and adjust rate limiting as needed.
5. Add the `[msv_magic_link_form]` shortcode to a page, or, if using Elementor Pro, add an email field with field ID `magiclinkemail` to a form and attach the "Magic Link Auth" action under "Actions After Submit".

== Frequently Asked Questions ==

= Does this replace WordPress's normal login? =

No — it's an additional passwordless entry point. Existing username/password login still works.

= What happens to a magic link if it's opened by an email security scanner before the real recipient clicks it? =

Nothing — the plugin's two-step confirm flow is specifically designed so a scanner's automated fetch (which never submits a form or executes JavaScript) can't consume the link. Only a genuine click-and-submit by the recipient does.

= Can I change the wording of the messages visitors see? =

Yes, on the Messaging tab. Every message shown to a visitor is editable, and if a translation file for your site's language is bundled, editing a message starts from that language's text.

= Where is data like the log and disposable-domain list stored? =

In the WordPress options table, under option names prefixed `msv_magic_link_auth_`. Deleting the plugin (not just deactivating it) removes all of it, including any stored magic-link tokens and rate-limit counters.

== Changelog ==

= 0.9.3 =
* The "Clear TotalPoll voter IPs now" and "Remove voter accounts now" buttons now open a review popup listing the actual IP addresses / accounts that will be affected (capped at 200, with a "showing X of Y" note), instead of just a count-only browser confirm dialog.
* Settings header now has a subtle bottom border and shadow, matching the card style used elsewhere on the page.
* Fixed the settings header still leaving a gap on its left edge in some admin themes, a leftover gray line under the tab row, and tab buttons not showing a pointer cursor on hover.

= 0.9.2 =
* Settings header is now full-width (edge-to-edge, no gutter), matching the rest of the redesigned admin UI.
* Flattened the tab bar: idle tabs have no border/background, a subtle hover tint, and the active tab shows only a colored bottom border. Removed the divider line below the tab row.

= 0.9.1 =
* Redesigned the settings screen: white rounded cards, a two-row sticky header (title above, tabs and Save/Update aligned on one row), and help-icon tooltips in place of many inline descriptions.
* Maintenance tab now splits into a main area and a right-hand sidebar: TotalPoll table detection, the table/column inputs, and "Run checks now" moved to the sidebar; renamed "Automatic purge schedule" to "Purge IP addresses" and "Delete all voters" to "Remove voter accounts".
* When WP-Cron is disabled on the site, both schedule sections are hidden (manual buttons still work) and a sidebar notice explains why, with a link to enable it.

= 0.9.0 =
* New Maintenance tab, moved out of Log: the TotalPoll voter IP cleanup section now lives here, alongside a new "Run checks now" button that reports table/column readiness as a page notice.
* Added scheduling for the TotalPoll IP purge: run manually, once at a chosen date/time, or repeating every N days between a start and end date, via WP-Cron. A lapsed one-time schedule is never auto-fired, even after reactivating the plugin.
* Added a "Delete all voters" maintenance action: permanently deletes voter accounts, either every account whose only role is Subscriber, or only accounts this plugin itself created (tracked via a new usermeta tag going forward). Same manual/scheduled options as the IP purge, fully independent schedule.
* Both destructive actions re-verify their preconditions at the moment they actually run (not just when scheduled), and log their outcome.

= 0.8.0 =
* Added a TotalPoll voter IP cleanup button (Log tab): clears voter IP addresses from TotalPoll Pro's log table after voting closes, leaving vote counts/results untouched. Table/column are auto-detected against your site's actual table prefix (never hardcoded) with an override for non-default table/column names, and the button stays disabled until a match is confirmed.

= 0.7.0 =
* Tabbed settings screen (Setup / Email & Blocklist / Messaging / Log) with a sticky header, page pickers instead of free-text paths, and Turnstile keys that disable instead of hiding.
* Generalized for distribution: no more site-specific defaults or hardcoded text, full translation support (`languages/`, ships a French translation), uninstall cleanup, and a readme.
* Fixed a data-loss bug where saving settings while a field was disabled (e.g. Turnstile keys, dev-mode fields) silently blanked/reset it instead of preserving the stored value.

= 0.6.0 =
* Disposable-email domain blocklist (bundled snapshot + self-service refresh + custom/allowlist), and email-address normalization (`+tag` and Gmail dot-stripping) to reduce multi-account abuse.

= 0.5.2 =
* Fixed a bug where the update checker could show "update available" and "already at latest version" simultaneously.

= 0.5.1 =
* Fixed the confirm button rendering on the wrong page / in the wrong position.

= 0.5.0 =
* Introduced the two-step magic-link confirm flow (peek-only GET, consume-on-POST) to stop email security scanners from silently invalidating links before real recipients click them.

= 0.4.x =
* Dark-themed HTML email matching site branding; configurable confirmation-page path.

= 0.3.x =
* Customizable status messages, floating dismissible toast notice, magic-link issuance/consumption logging, time-based log retention.

= 0.3.0 =
* Initial tracked release: passwordless magic-link auth with rate limiting, Cloudflare Turnstile, and a protected page, via shortcode and Elementor Pro form action.
