<?php
/**
 * Security Dashboard Class
 *
 * Handles the admin dashboard interface for the security plugin, providing a
 * centralized view of security metrics, status indicators, and management options.
 *
 * @package WP_Security_Hardening
 * @subpackage Admin
 * @since 1.0.0
 */

// Prevent direct access to this file.
if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Direct access not permitted.' );
}

/**
 * Class WP_Security_Dashboard
 *
 * Manages the security dashboard interface and functionality.
 *
 * @since 1.0.0
 */
class WP_Security_Dashboard {

	/**
	 * The capability required to access this dashboard.
	 *
	 * @since 1.0.0
	 * @var string
	 */
	private $capability = 'manage_options';

	/**
	 * Scanner component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_Scanner
	 */
	private $scanner;

	/**
	 * Threat intelligence component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_Threat_Intelligence
	 */
	private $threat_intel;

	/**
	 * File monitor component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_File_Monitor
	 */
	private $file_monitor;

	/**
	 * Quarantine manager component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_Quarantine_Manager
	 */
	private $quarantine;

	/**
	 * Core repair component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_Core_Repair
	 */
	private $core_repair;

	/**
	 * Health monitor component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_Health_Monitor
	 */
	private $health_monitor;

	/**
	 * API manager component instance.
	 *
	 * @since 1.0.0
	 * @var WP_Security_API_Manager
	 */
	private $api_manager;

	/**
	 * Security metrics data.
	 *
	 * @since 1.0.0
	 * @var array
	 */
	private $metrics;

	/**
	 * Status indicators data.
	 *
	 * @since 1.0.0
	 * @var array
	 */
	private $status_indicators;

	/**
	 * Constructor - Initialize dashboard components and set up WordPress hooks.
	 *
	 * @since 1.0.0
	 * @param WP_Security_API_Manager         $api_manager    API manager instance.
	 * @param WP_Security_Scanner             $scanner        Scanner instance.
	 * @param WP_Security_Threat_Intelligence $threat_intel   Threat intelligence instance.
	 * @param WP_Security_File_Monitor        $file_monitor   File monitor instance.
	 * @param WP_Security_Quarantine_Manager  $quarantine     Quarantine manager instance.
	 * @param WP_Security_Core_Repair         $core_repair    Core repair instance.
	 * @param WP_Security_Health_Monitor      $health_monitor Health monitor instance.
	 */
	public function __construct(
		WP_Security_API_Manager $api_manager,
		WP_Security_Scanner $scanner,
		WP_Security_Threat_Intelligence $threat_intel,
		WP_Security_File_Monitor $file_monitor,
		WP_Security_Quarantine_Manager $quarantine,
		WP_Security_Core_Repair $core_repair,
		WP_Security_Health_Monitor $health_monitor
	) {
		$this->api_manager    = $api_manager;
		$this->scanner        = $scanner;
		$this->threat_intel   = $threat_intel;
		$this->file_monitor   = $file_monitor;
		$this->quarantine     = $quarantine;
		$this->core_repair    = $core_repair;
		$this->health_monitor = $health_monitor;

		$this->init_metrics();
		$this->init_status_indicators();

		// Add WordPress action hooks.
		add_action( 'admin_menu', array( $this, 'add_dashboard_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_dashboard_assets' ) );
		add_action( 'wp_ajax_wp_security_scan', array( $this, 'handle_scan_request' ) );
		add_action( 'wp_ajax_wp_security_clean', array( $this, 'handle_clean_request' ) );
		add_action( 'wp_ajax_wp_security_quarantine', array( $this, 'handle_quarantine_request' ) );
		add_action( 'wp_ajax_auto_fix_issues', array( $this, 'handle_auto_fix_request' ) );
	}

	/**
	 * Initialize security metrics for monitoring.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function init_metrics() {
		$this->metrics = array(
			'files_scanned'  => $this->scanner->get_scan_count(),
			'threats_found'  => $this->threat_intel->get_threat_count(),
			'last_scan_time' => $this->scanner->get_last_scan_time(),
			'security_score' => $this->health_monitor->calculate_security_score(),
			'wp_version'     => get_bloginfo( 'version' ),
			'php_version'    => PHP_VERSION,
			'api_usage'      => $this->api_manager->get_api_usage(),
			'malware_stats'  => $this->scanner->get_malware_stats(),
		);
	}

	/**
	 * Initialize status indicators for security monitoring.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function init_status_indicators() {
		$this->status_indicators = array(
			'admin_ssl'       => $this->check_admin_ssl(),
			'debug_mode'      => $this->check_debug_mode(),
			'auto_updates'    => $this->check_auto_updates(),
			'file_editing'    => $this->check_file_editing(),
			'api_limits'      => $this->check_api_limits(),
			'malware_status'  => $this->check_malware_status(),
			'obfuscated_code' => $this->check_obfuscated_code(),
		);
	}

	/**
	 * Add dashboard menu items to WordPress admin.
	 *
	 * Creates the main security menu item and its submenus in the WordPress
	 * admin dashboard.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function add_dashboard_menu() {
		add_menu_page(
			esc_html__( 'Security Dashboard', 'wp-security-hardening' ),
			esc_html__( 'Security', 'wp-security-hardening' ),
			$this->capability,
			'wp-security-dashboard',
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			3
		);

		add_submenu_page(
			'wp-security-dashboard',
			esc_html__( 'Security Settings', 'wp-security-hardening' ),
			esc_html__( 'Settings', 'wp-security-hardening' ),
			$this->capability,
			'wp-security-settings',
			array( $this, 'render_settings' )
		);
	}

	/**
	 * Enqueue dashboard assets (CSS and JavaScript).
	 *
	 * Loads the necessary CSS and JavaScript files for the security dashboard.
	 *
	 * @since 1.0.0
	 * @param string $hook The current admin page hook.
	 * @return void
	 */
	public function enqueue_dashboard_assets( $hook ) {
		if ( 'toplevel_page_wp-security-dashboard' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'wp-security-dashboard',
			plugins_url( 'css/dashboard.css', __FILE__ ),
			array(),
			WP_SECURITY_VERSION
		);

		wp_enqueue_script(
			'wp-security-dashboard',
			plugins_url( 'js/dashboard.js', __FILE__ ),
			array( 'jquery', 'wp-api' ),
			WP_SECURITY_VERSION,
			true
		);

		wp_localize_script(
			'wp-security-dashboard',
			'wpSecurityDashboard',
			array(
				'nonce'   => wp_create_nonce( 'wp_security_dashboard' ),
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'i18n'    => array(
					'scanning'     => esc_html__( 'Scanning...', 'wp-security-hardening' ),
					'scanComplete' => esc_html__( 'Scan Complete', 'wp-security-hardening' ),
					'error'        => esc_html__( 'Error', 'wp-security-hardening' ),
				),
			)
		);
	}

	/**
	 * Render the main security dashboard.
	 *
	 * Displays the security dashboard interface, including security metrics and
	 * status indicators.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function render_dashboard() {
		if ( ! current_user_can( $this->capability ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-security-hardening' ) );
		}

		$this->update_metrics();
		include plugin_dir_path( __FILE__ ) . 'templates/dashboard.php';
	}

	/**
	 * Render the settings page.
	 *
	 * Displays the security settings page, allowing users to configure security
	 * options.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function render_settings() {
		if ( ! current_user_can( $this->capability ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-security-hardening' ) );
		}

		include plugin_dir_path( __FILE__ ) . 'templates/settings.php';
	}

	/**
	 * Update security metrics with latest data.
	 *
	 * Retrieves the latest security metrics and updates the dashboard display.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function update_metrics() {
		$this->metrics['files_scanned']  = $this->scanner->get_scan_count();
		$this->metrics['threats_found']  = $this->threat_intel->get_threat_count();
		$this->metrics['last_scan_time'] = $this->scanner->get_last_scan_time();
		$this->metrics['security_score'] = $this->health_monitor->calculate_security_score();
	}

	/**
	 * Handle malware scan request
	 */
	public function handle_scan_request() {
		check_ajax_referer( 'wp_security_nonce', 'nonce' );

		if ( ! current_user_can( $this->capability ) ) {
			wp_send_json_error( 'Insufficient permissions' );
		}

		// Check API limits before scanning.
		if ( ! $this->api_manager->can_make_request( 'scan' ) ) {
			wp_send_json_error( 'API limit reached. Please try again later.' );
		}

		$scan_results = $this->scanner->run_full_scan();
		$this->api_manager->record_api_usage( 'scan' );

		wp_send_json_success( $scan_results );
	}

	/**
	 * Handle malware cleaning request
	 */
	public function handle_clean_request() {
		check_ajax_referer( 'wp_security_nonce', 'nonce' );

		if ( ! current_user_can( $this->capability ) ) {
			wp_send_json_error( 'Insufficient permissions' );
		}

		// Check API limits before cleaning.
		if ( ! $this->api_manager->can_make_request( 'clean' ) ) {
			wp_send_json_error( 'API limit reached. Please try again later.' );
		}

		$clean_results = $this->scanner->clean_detected_threats();
		$this->api_manager->record_api_usage( 'clean' );

		wp_send_json_success( $clean_results );
	}

	/**
	 * Check if file permissions are secure.
	 *
	 * Verifies that file permissions are set correctly to prevent unauthorized
	 * access.
	 *
	 * @since 1.0.0
	 * @return bool True if file permissions are secure, false otherwise.
	 */
	private function check_file_permissions() {
		$wp_config_file = ABSPATH . 'wp-config.php';
		$htaccess_file  = ABSPATH . '.htaccess';
		$secure         = true;

		if ( file_exists( $wp_config_file ) ) {
			$wp_config_perms = substr( sprintf( '%o', fileperms( $wp_config_file ) ), -4 );
			if ( '0400' !== $wp_config_perms && '0440' !== $wp_config_perms ) {
				$secure = false;
			}
		}

		if ( file_exists( $htaccess_file ) ) {
			$htaccess_perms = substr( sprintf( '%o', fileperms( $htaccess_file ) ), -4 );
			if ( '0444' !== $htaccess_perms ) {
				$secure = false;
			}
		}

		return $secure;
	}

	/**
	 * Check if automatic updates are enabled.
	 *
	 * Verifies that automatic updates are enabled for WordPress core, plugins,
	 * and themes.
	 *
	 * @since 1.0.0
	 * @return bool True if auto updates are enabled, false otherwise.
	 */
	private function check_auto_updates() {
		return (
			wp_is_auto_update_enabled_for_type( 'core' ) &&
			wp_is_auto_update_enabled_for_type( 'plugin' ) &&
			wp_is_auto_update_enabled_for_type( 'theme' )
		);
	}

	/**
	 * Check if file editing is disabled.
	 *
	 * Verifies that file editing is disabled to prevent unauthorized changes.
	 *
	 * @since 1.0.0
	 * @return bool True if file editing is disabled, false otherwise.
	 */
	private function check_file_editing() {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	}

	/**
	 * Get security metrics for display.
	 *
	 * Returns the current security metrics for display on the dashboard.
	 *
	 * @since 1.0.0
	 * @return array Array of security metrics.
	 */
	public function get_metrics() {
		return $this->metrics;
	}

	/**
	 * Get security status indicators.
	 *
	 * Returns the current security status indicators for display on the dashboard.
	 *
	 * @since 1.0.0
	 * @return array Array of security status indicators.
	 */
	public function get_status_indicators() {
		return $this->status_indicators;
	}
}
