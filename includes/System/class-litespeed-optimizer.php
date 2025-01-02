<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_LiteSpeed_Optimizer {
	private $cache_config = array();
	private $edge_rules   = array();
	private $esi_blocks   = array();
	private $purge_queue  = array();

	public function __construct() {
		// Initialize cache configuration
		$this->init_cache_config();

		// Set up hooks
		add_action( 'init', array( $this, 'setup_litespeed_hooks' ) );
		add_action( 'wp_security_scan_complete', array( $this, 'handle_scan_complete' ) );
		add_action( 'wp_security_malware_cleaned', array( $this, 'purge_cache_after_cleanup' ) );

		// Add security headers
		add_action( 'litespeed_init', array( $this, 'add_security_headers' ) );
	}

	private function init_cache_config() {
		$this->cache_config = array(
			'cache_mobile'  => true,
			'cache_browser' => true,
			'cache_feed'    => true,
			'cache_rest'    => true,
			'cache_login'   => false,
			'cache_admin'   => false,
			'cache_object'  => true,
			'esi'           => true,
			'edge_mode'     => true,
		);

		// Security-focused edge rules
		$this->edge_rules = array(
			'block_bad_bots'           => true,
			'block_bad_refs'           => true,
			'block_bad_ips'            => true,
			'rate_limiting'            => true,
			'dynamic_request_check'    => true,
			'xss_prevention'           => true,
			'sql_injection_prevention' => true,
		);

		// ESI blocks for dynamic content
		$this->esi_blocks = array(
			'user_status',
			'security_status',
			'notification_center',
			'real_time_stats',
		);
	}

	public function setup_litespeed_hooks() {
		// Only proceed if LiteSpeed is active
		if ( ! $this->is_litespeed_active() ) {
			return;
		}

		// Cache control
		add_action( 'litespeed_init_excludes', array( $this, 'set_cache_excludes' ) );
		add_action( 'litespeed_init_cookies', array( $this, 'set_cookie_rules' ) );
		add_action( 'litespeed_init_esi', array( $this, 'setup_esi_blocks' ) );

		// Security rules
		add_action( 'litespeed_init_conf', array( $this, 'set_security_rules' ) );
		add_filter( 'litespeed_vary', array( $this, 'add_security_vary' ) );

		// Performance optimization
		add_action( 'litespeed_optimize', array( $this, 'optimize_settings' ) );
	}

	public function is_litespeed_active() {
		return (
			isset( $_SERVER['SERVER_SOFTWARE'] ) &&
			stripos( $_SERVER['SERVER_SOFTWARE'], 'LiteSpeed' ) !== false
		) || (
			isset( $_SERVER['HTTP_X_LSCACHE'] ) &&
			$_SERVER['HTTP_X_LSCACHE']
		);
	}

	public function set_cache_excludes() {
		// Security-sensitive paths
		$excludes = array(
			'/wp-admin/',
			'/wp-login.php',
			'/wp-cron.php',
			'/xmlrpc.php',
			'/wp-json/wp/v2/users',
			'/wp-security-hardening/admin/*',
		);

		foreach ( $excludes as $path ) {
			do_action( 'litespeed_control_set_nocache', $path );
		}
	}

	public function set_cookie_rules() {
		// Security cookies that should vary cache
		$cookies = array(
			'wordpress_logged_in_',
			'wordpress_sec_',
			'wp_security_token',
			'wp_security_2fa',
		);

		foreach ( $cookies as $cookie ) {
			do_action( 'litespeed_conf_set', 'cache-vary_cookies[]', $cookie );
		}
	}

	public function setup_esi_blocks() {
		foreach ( $this->esi_blocks as $block ) {
			do_action( 'litespeed_conf_set', 'esi_enabled', true );
			do_action( 'litespeed_esi_register', "security-{$block}", array( $this, "render_esi_{$block}" ) );
		}
	}

	public function set_security_rules() {
		// Edge security rules
		foreach ( $this->edge_rules as $rule => $enabled ) {
			if ( $enabled ) {
				do_action( 'litespeed_conf_set', "edge_{$rule}", true );
			}
		}

		// Custom security rules
		$this->add_custom_security_rules();
	}

	private function add_custom_security_rules() {
		// Block PHP execution in uploads
		$rules = array(
			'location /wp-content/uploads/ {',
			'    deny *.php;',
			'}',
			// Protect wp-config.php
			'location = /wp-config.php {',
			'    deny all;',
			'}',
			// Prevent directory listing
			'autoindex off;',
		);

		foreach ( $rules as $rule ) {
			do_action( 'litespeed_conf_append', 'rules', $rule );
		}
	}

	public function add_security_headers() {
		$headers = array(
			'X-Frame-Options'         => 'SAMEORIGIN',
			'X-Content-Type-Options'  => 'nosniff',
			'X-XSS-Protection'        => '1; mode=block',
			'Referrer-Policy'         => 'strict-origin-when-cross-origin',
			'Permissions-Policy'      => 'geolocation=(), microphone=(), camera=()',
			'Content-Security-Policy' => $this->get_csp_policy(),
		);

		foreach ( $headers as $header => $value ) {
			do_action( 'litespeed_conf_set', "headers_{$header}", $value );
		}
	}

	private function get_csp_policy() {
		return "default-src 'self'; " .
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' *.wordpress.org *.google-analytics.com; " .
				"style-src 'self' 'unsafe-inline' *.wordpress.org; " .
				"img-src 'self' data: *.wordpress.org *.gravatar.com; " .
				"connect-src 'self' *.wordpress.org; " .
				"font-src 'self'; " .
				"frame-src 'self'; " .
				"media-src 'self'";
	}

	public function add_security_vary() {
		return array(
			'User-Agent',
			'Cookie',
			'X-Forwarded-Proto',
			'X-Security-Token',
		);
	}

	public function optimize_settings() {
		// Cache settings
		foreach ( $this->cache_config as $key => $value ) {
			do_action( 'litespeed_conf_set', "cache_{$key}", $value );
		}

		// Performance settings
		$performance = array(
			'css_minify'      => true,
			'css_combine'     => true,
			'js_minify'       => true,
			'js_combine'      => true,
			'html_minify'     => true,
			'optm_qs_rm'      => true,
			'optm_emoji_rm'   => true,
			'optm_ggfonts_rm' => true,
		);

		foreach ( $performance as $key => $value ) {
			do_action( 'litespeed_conf_set', "optm_{$key}", $value );
		}
	}

	public function handle_scan_complete( $scan_results ) {
		if ( ! empty( $scan_results['modified_files'] ) ) {
			$this->purge_related_cache( $scan_results['modified_files'] );
		}
	}

	public function purge_cache_after_cleanup( $cleaned_files ) {
		if ( ! empty( $cleaned_files ) ) {
			$this->purge_related_cache( $cleaned_files );
		}

		// Also purge homepage and any related URLs
		do_action( 'litespeed_purge_all' );
	}

	private function purge_related_cache( $files ) {
		foreach ( $files as $file ) {
			// Get URLs that might be affected
			$urls = $this->get_related_urls( $file );

			foreach ( $urls as $url ) {
				do_action( 'litespeed_purge_url', $url );
			}
		}
	}

	private function get_related_urls( $file ) {
		$urls = array();

		// Add homepage
		$urls[] = home_url( '/' );

		// If it's a template file, purge all pages
		if ( strpos( $file, '/themes/' ) !== false ) {
			$urls[] = home_url( '/*' );
		}

		// If it's a plugin file, check for specific patterns
		if ( strpos( $file, '/plugins/' ) !== false ) {
			// Add plugin-specific URLs
			$plugin_dir = basename( dirname( $file ) );
			$urls[]     = home_url( "/wp-json/{$plugin_dir}/*" );
		}

		return $urls;
	}

	public function render_esi_user_status() {
		// Render user-specific status
		if ( is_user_logged_in() ) {
			$user = wp_get_current_user();
			include plugin_dir_path( __FILE__ ) . '../templates/esi/user-status.php';
		}
	}

	public function render_esi_security_status() {
		// Render security status
		$status = WP_Security_Health_Monitor::get_instance()->get_security_status();
		include plugin_dir_path( __FILE__ ) . '../templates/esi/security-status.php';
	}

	public function render_esi_notification_center() {
		// Render notifications
		$notifications = WP_Security_Notifications::get_instance()->get_recent_notifications();
		include plugin_dir_path( __FILE__ ) . '../templates/esi/notifications.php';
	}

	public function render_esi_real_time_stats() {
		// Render real-time statistics
		$stats = WP_Security_Health_Monitor::get_instance()->get_real_time_stats();
		include plugin_dir_path( __FILE__ ) . '../templates/esi/real-time-stats.php';
	}
}
