<?php
/**
 * WP Security Hardening - Security Settings Class
 *
 * @package    WP_Security_Hardening
 * @subpackage Admin
 * @since      1.0.0
 * @version    1.0.0
 *
 * This file is part of the WP Security Hardening plugin which provides
 * enhanced security features for WordPress installations. It contains the
 * security settings management class that handles plugin configuration,
 * API integrations, and security control options.
 *
 * @link       https://github.com/your-repository/wp-security-hardening
 * @author     Codeium
 * @copyright  2024 Codeium
 * @license    GPL-2.0+
 */

/**
 * WP Security Hardening Plugin - Security Settings Class
 *
 * This file contains the WP_Security_Settings class which handles the admin settings
 * interface for the WordPress Security Hardening plugin. It manages security configuration
 * options and provides an administrative interface for site administrators.
 *
 * @package WP_Security_Hardening
 * @subpackage Admin
 * @since 1.0.0
 * @version 1.0.0
 * @author Codeium
 * @license GPL-2.0+
 * @link https://github.com/your-repository/wp-security-hardening
 *
 * @wordpress-plugin
 */


if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-settings.php';

use WP_Security\Core\Logger;

class WP_Security_Admin_Settings extends WP_Security_Settings {

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Option group name
	 *
	 * @var string
	 */
	private string $option_group = 'wp_security_options';

	/**
	 * Settings page slug
	 *
	 * @var string
	 */
	private string $page = 'wp-security-settings';

	/**
	 * Logger instance
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Network active status
	 *
	 * @var bool
	 */
	private bool $is_network_active = false;

	/**
	 * Network sites
	 *
	 * @var array
	 */
	private array $network_sites = array();

	/**
	 * Error messages
	 *
	 * @var array
	 */
	private array $errors = array();

	/**
	 * Success messages
	 *
	 * @var array
	 */
	private array $messages = array();

	/**
	 * @var array<string, mixed>
	 */
	private array $settings = [];

	/**
	 * @var array<string, array{id: string, title: string, description: string}>
	 */
	private array $sections = [];

	/**
	 * @var array<string, array{id: string, title: string, type: string, section: string, options?: array<string, string>}>
	 */
	private array $fields = [];

	/**
	 * Get the singleton instance
	 *
	 * @return self
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor - Initialize settings and dependencies
	 */
	public function __construct() {
		parent::__construct();
		// Initialize dependencies
		$this->logger = new Logger();
		
		// Initialize network settings
		$this->init_network_settings();

		// Register hooks
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'init_settings' ) );
		add_action( 'admin_notices', array( $this, 'display_messages' ) );
		add_action( 'wp_ajax_verify_api_key', array( $this, 'ajax_verify_api_key' ) );

		// Add network sync handler
		add_action( 'wp_security_sync_settings', array( $this, 'sync_settings' ) );
	}

	/**
	 * Initialize plugin
	 */
	public function init(): void {
		// Only run in admin context
		if (!is_admin()) {
			return;
		}

		add_action('admin_init', array($this, 'init_settings'));
		add_action('admin_menu', array($this, 'add_settings_page'));
		add_action('wp_ajax_verify_api_key', array($this, 'ajax_verify_api_key'));
	}

	/**
	 * Initialize network settings
	 *
	 * @return void
	 */
	private function init_network_settings(): void {
		// Initialize network-related settings if needed
		$this->is_network_active = false;
		$this->network_sites = array();
	}

	/**
	 * Initialize settings with validation
	 *
	 * @return void
	 */
	public function init_settings(): void {
		try {
			// Initialize basic settings
			$this->register_basic_settings();
			
			// Register settings sections
			$this->register_settings_sections();
			
			// Add settings fields
			$this->add_settings_fields();
			
		} catch (Exception $e) {
			$this->log_error($e->getMessage());
		}
	}

	/**
	 * Register basic plugin settings
	 *
	 * @return void
	 */
	private function register_basic_settings(): void {
		// Basic initialization without WordPress dependencies
		$this->settings = array(
			'api_key' => '',
			'scan_frequency' => 'daily',
			'notification_email' => '',
			'security_level' => 'medium'
		);
	}

	/**
	 * Register settings sections
	 *
	 * @return void
	 */
	private function register_settings_sections(): void {
		$this->sections = array(
			'general' => array(
				'id' => 'general',
				'title' => 'General Settings',
				'description' => 'Configure general security settings'
			),
			'scanning' => array(
				'id' => 'scanning',
				'title' => 'Scanning Options',
				'description' => 'Configure malware scanning options'
			)
		);
	}

	/**
	 * Add settings fields
	 *
	 * @return void
	 */
	private function add_settings_fields(): void {
		$this->fields = array(
			'api_key' => array(
				'id' => 'api_key',
				'title' => 'API Key',
				'type' => 'text',
				'section' => 'general'
			),
			'scan_frequency' => array(
				'id' => 'scan_frequency',
				'title' => 'Scan Frequency',
				'type' => 'select',
				'section' => 'scanning',
				'options' => array(
					'daily' => 'Daily',
					'weekly' => 'Weekly',
					'monthly' => 'Monthly'
				)
			)
		);
	}

	/**
	 * Validate API key format and test connectivity
	 *
	 * @param string $key The API key to validate
	 * @return string The validated API key
	 */
	public function validate_api_key( $key ): string {
		if ( empty( $key ) ) {
			return '';
		}

		// Basic format validation
		if ( ! preg_match( '/^[a-zA-Z0-9_-]+$/', $key ) ) {
			add_settings_error(
				'wp_security_options',
				'invalid_api_key',
				'Invalid API key format'
			);
			return '';
		}

		try {
			// Test API connectivity
			$response = wp_remote_get(
				'https://www.virustotal.com/vtapi/v2/file/scan',
				array(
					'headers' => array(
						'x-apikey' => $key,
					),
				)
			);

			if ( is_wp_error( $response ) ) {
				throw new Exception( $response->get_error_message() );
			}

			$code = wp_remote_retrieve_response_code( $response );
			if ( $code !== 200 ) {
				throw new Exception( 'API key validation failed with status: ' . $code );
			}

			return $key;

		} catch ( Exception $e ) {
			$this->log_error( 'API key validation failed: ' . $e->getMessage() );
			add_settings_error(
				'wp_security_options',
				'api_validation_failed',
				'API key validation failed: ' . $e->getMessage()
			);
			return '';
		}
	}

	/**
	 * Validate scan frequency
	 *
	 * @param string $frequency The scan frequency to validate
	 * @return string The validated scan frequency
	 */
	public function validate_scan_frequency( $frequency ): string {
		if ( empty( $frequency ) ) {
			return '';
		}

		// Basic format validation
		if ( ! in_array( $frequency, array( 'hourly', 'twicedaily', 'daily', 'weekly' ) ) ) {
			add_settings_error(
				'wp_security_options',
				'invalid_scan_frequency',
				'Invalid scan frequency'
			);
			return '';
		}

		return $frequency;
	}

	/**
	 * Validate checkbox value
	 *
	 * @param string $value The checkbox value to validate
	 * @return string The validated checkbox value
	 */
	public function validate_checkbox( $value ): string {
		if ( empty( $value ) ) {
			return '';
		}

		// Basic format validation
		if ( ! in_array( $value, array( '1', '0' ) ) ) {
			add_settings_error(
				'wp_security_options',
				'invalid_checkbox_value',
				'Invalid checkbox value'
			);
			return '';
		}

		return $value;
	}

	/**
	 * AJAX handler for API key verification
	 */
	public function ajax_verify_api_key(): void {
		try {
			if (!function_exists('check_ajax_referer') || !function_exists('current_user_can')) {
				wp_send_json_error('WordPress functions not available');
				return;
			}

			check_ajax_referer('wp_security_nonce', 'nonce');

			if (!current_user_can('manage_options')) {
				wp_send_json_error('Insufficient permissions');
				return;
			}

			$key_type = isset($_POST['key_type']) ? sanitize_text_field(wp_unslash($_POST['key_type'])) : '';
			$api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';

			if (empty($key_type) || empty($api_key)) {
				wp_send_json_error('Invalid parameters');
				return;
			}

			$result = $this->verify_api_key($key_type, $api_key);
			wp_send_json_success($result);

		} catch (Exception $e) {
			$this->log_error($e->getMessage());
			wp_send_json_error($e->getMessage());
		}
	}

	/**
	 * Log error messages
	 *
	 * @param string $message Error message to log
	 */
	private function log_error($message): void {
		if ($this->logger && method_exists($this->logger, 'log')) {
			$this->logger->log('error', $message);
		}
	}

	/**
	 * Verify API key functionality
	 *
	 * @param string $key_type The type of API key
	 * @param string $api_key The API key to verify
	 * @return array Verification result
	 * @throws Exception If verification fails
	 */
	private function verify_api_key( $key_type, $api_key ): array {
		if ( empty( $api_key ) ) {
			throw new Exception( 'API key cannot be empty' );
		}

		// Verify key based on type
		switch ( $key_type ) {
			case 'virustotal':
				$endpoint = 'https://www.virustotal.com/vtapi/v2/file/scan';
				$headers  = array( 'x-apikey' => $api_key );
				break;
			case 'wpscan':
				$endpoint = 'https://wpscan.com/api/v3/status';
				$headers  = array( 'Authorization' => $api_key );
				break;
			default:
				throw new Exception( 'Invalid API key type' );
		}

		$response = wp_remote_get( $endpoint, array( 'headers' => $headers ) );

		if ( is_wp_error( $response ) ) {
			throw new Exception( $response->get_error_message() );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			throw new Exception( 'API verification failed with status: ' . $code );
		}

		return array(
			'status'  => 'success',
			'message' => 'API key verified successfully',
		);
	}

	/**
	 * Display admin notices
	 */
	public function display_messages(): void {
		if ( ! empty( $this->errors ) ) {
			foreach ( $this->errors as $error ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
			}
		}

		if ( ! empty( $this->messages ) ) {
			foreach ( $this->messages as $message ) {
				echo '<div class="notice notice-success"><p>' . esc_html( $message ) . '</p></div>';
			}
		}
	}

	/**
	 * Get API key with error handling
	 *
	 * @param string $key_type The type of API key to retrieve
	 * @return string The API key or empty string if not found
	 */
	public static function get_api_key( $key_type ): string {
		try {
			switch ( $key_type ) {
				case 'virustotal':
					return get_option( 'wp_security_virustotal_api_key', '' );
				case 'wpscan':
					return get_option( 'wp_security_wpscan_api_key', '' );
				case 'abuseipdb':
					return get_option( 'wp_security_abuseipdb_key', '' );
				case 'urlscan':
					return get_option( 'wp_security_urlscan_key', '' );
				case 'phishtank':
					return get_option( 'wp_security_phishtank_key', '' );
				default:
					throw new Exception( 'Invalid API key type: ' . $key_type );
			}
		} catch ( Exception $e ) {
			error_log( 'Error retrieving API key: ' . $e->getMessage() );
			return '';
		}
	}

	/**
	 * Check if required API keys are configured
	 *
	 * @return bool True if all required keys are set
	 */
	public function check_required_keys(): bool {
		$required_keys = array(
			'virustotal',
			'wpscan',
		);

		foreach ( $required_keys as $key_type ) {
			if ( empty( self::get_api_key( $key_type ) ) ) {
				$this->errors[] = sprintf(
					'Required API key missing: %s. Please configure it in the security settings.',
					ucfirst( $key_type )
				);
				return false;
			}
		}

		return true;
	}

	/**
	 * Add settings page
	 */
	public function add_settings_page(): void {
		add_submenu_page(
			'wp-security-dashboard',
			'Security Settings',
			'Settings',
			'manage_options',
			$this->page,
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Render settings page
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( isset( $_GET['settings-updated'] ) ) {
			add_settings_error(
				'wp_security_messages',
				'wp_security_message',
				'Settings Saved',
				'updated'
			);
		}

		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<?php settings_errors( 'wp_security_messages' ); ?>

			<form action="options.php" method="post">
				<?php
				settings_fields( $this->option_group );
				do_settings_sections( $this->page );
				submit_button( 'Save Settings' );
				?>
			</form>

			<div class="api-instructions">
				<h2>API Key Instructions</h2>
				<?php
				if ( empty( $this->get_api_key( 'virustotal' ) ) ) {
					?>
					<p><strong>Important:</strong> Without a valid VirusTotal API key, the plugin will not function.</p>
					<?php
				}

				?>
				<div class="api-instruction-block">
					<h3>VirusTotal API Key (Required)</h3>
					<ol>
						<li>Visit <a href="https://www.virustotal.com/gui/join-us" target="_blank">VirusTotal</a> and create an account</li>
						<li>Go to your profile</li>
						<li>Get your API key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Scanning files and URLs for malware</p>
				</div>

				<div class="api-instruction-block">
					<h3>WPScan API Key (Required)</h3>
					<ol>
						<li>Visit <a href="https://wpscan.com/api" target="_blank">WPScan</a></li>
						<li>Create an account</li>
						<li>Get your API token</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> WordPress vulnerability scanning</p>
				</div>

				<div class="api-instruction-block">
					<h3>AbuseIPDB API Key (Recommended)</h3>
					<ol>
						<li>Visit <a href="https://www.abuseipdb.com/pricing" target="_blank">AbuseIPDB</a></li>
						<li>Sign up for an account</li>
						<li>Get your API key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Checking IP addresses against known malicious sources</p>
				</div>

				<div class="api-instruction-block">
					<h3>URLScan.io API Key (Recommended)</h3>
					<ol>
						<li>Visit <a href="https://urlscan.io/user/signup" target="_blank">URLScan.io</a> and create an account</li>
						<li>Go to your profile settings</li>
						<li>Generate an API key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Scanning URLs in comments and posts</p>
				</div>

				<div class="api-instruction-block">
					<h3>PhishTank API Key (Optional)</h3>
					<ol>
						<li>Visit <a href="https://www.phishtank.com/register.php" target="_blank">PhishTank</a> and register</li>
						<li>Apply for an API key</li>
						<li>Once approved, copy your key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Checking URLs against known phishing sites</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render API section
	 *
	 * @param array $args Section arguments
	 */
	public function render_api_section( $args ): void {
		?>
		<p>Enter your API keys below. These are required for advanced security features.</p>
		<?php
	}

	/**
	 * Render scan section
	 *
	 * @param array $args Section arguments
	 */
	public function render_scan_section( $args ): void {
		?>
		<p>Configure how the security scanner operates.</p>
		<?php
	}

	/**
	 * Render API field
	 *
	 * @param array $args Field arguments
	 */
	public function render_api_field( $args ): void {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<input
			type="password"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="<?php echo esc_attr( $value ); ?>"
			class="regular-text"
		>
		<?php
	}

	/**
	 * Render frequency field
	 *
	 * @param array $args Field arguments
	 */
	public function render_frequency_field( $args ): void {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<select
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
		>
			<option value="hourly" <?php selected( $value, 'hourly' ); ?>>Hourly</option>
			<option value="twicedaily" <?php selected( $value, 'twicedaily' ); ?>>Twice Daily</option>
			<option value="daily" <?php selected( $value, 'daily' ); ?>>Daily</option>
			<option value="weekly" <?php selected( $value, 'weekly' ); ?>>Weekly</option>
		</select>
		<?php
	}

	/**
	 * Render checkbox field
	 *
	 * @param array $args Field arguments
	 */
	public function render_checkbox_field( $args ): void {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<input
			type="checkbox"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="1"
			<?php checked( 1, $value ); ?>
		>
		<label for="<?php echo esc_attr( $option ); ?>">
			<?php echo esc_html( $args['description'] ); ?>
		</label>
		<?php
	}

	/**
	 * Sync settings across network sites
	 *
	 * @param array $settings Settings to sync
	 * @return bool Success status
	 */
	public function sync_settings( array $settings ): bool {
		if ( ! $this->is_network_active ) {
			return false;
		}

		foreach ( $this->network_sites as $site ) {
			switch_to_blog( $site->blog_id );
			foreach ( $settings as $option => $value ) {
				update_option( $option, $value );
			}
			restore_current_blog();
		}

		$this->logger->log(
			'settings_sync',
			'Network settings synchronized',
			'info',
			array( 'settings' => array_keys( $settings ) )
		);

		return true;
	}

	/**
	 * Get settings from a specific site
	 *
	 * @param int   $site_id Site ID
	 * @param array $options Options to retrieve
	 * @return array Site settings
	 */
	public function get_site_settings( int $site_id, array $options ): array {
		if ( ! $this->is_network_active ) {
			return array();
		}

		$settings = array();
		
		switch_to_blog( $site_id );
		foreach ( $options as $option ) {
			$settings[$option] = get_option( $option );
		}
		restore_current_blog();
		
		return $settings;
	}
}
