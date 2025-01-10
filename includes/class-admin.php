<?php
/**
 * The admin-specific functionality of the plugin.
 *
 * @package WP_Security_Hardening
 * @subpackage WP_Security_Hardening/admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The admin-specific functionality of the plugin.
 *
 * @package WP_Security_Hardening
 * @subpackage WP_Security_Hardening/admin
 */
class WP_Security_Hardening_Admin {
	/**
	 * The single instance of the class.
	 *
	 * @var WP_Security_Hardening_Admin
	 */
	private static $instance = null;

	/**
	 * The plugin settings.
	 *
	 * @var WP_Security_Hardening_Settings
	 */
	private $settings;

	/**
	 * Initialize the class and set its properties.
	 */
	private function __construct() {
		$this->settings = new WP_Security_Hardening_Settings();

		// Add menu items
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );

		// Register settings
		add_action( 'admin_init', array( $this, 'register_settings' ) );

		// Add action links
		add_filter( 'plugin_action_links_' . WP_SECURITY_PLUGIN_BASENAME, array( $this, 'add_action_links' ) );
	}

	/**
	 * Main WP_Security_Hardening_Admin Instance.
	 *
	 * Ensures only one instance of WP_Security_Hardening_Admin is loaded or can be loaded.
	 *
	 * @return WP_Security_Hardening_Admin Main instance
	 */
	public static function get_instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Add menu items.
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'Security Hardening', 'wp-security-hardening' ),
			__( 'Security', 'wp-security-hardening' ),
			'manage_options',
			'wp-security-hardening',
			array( $this, 'display_main_page' ),
			'dashicons-shield',
			100
		);

		add_submenu_page(
			'wp-security-hardening',
			__( 'Security Dashboard', 'wp-security-hardening' ),
			__( 'Dashboard', 'wp-security-hardening' ),
			'manage_options',
			'wp-security-hardening',
			array( $this, 'display_main_page' )
		);

		add_submenu_page(
			'wp-security-hardening',
			__( 'Security Settings', 'wp-security-hardening' ),
			__( 'Settings', 'wp-security-hardening' ),
			'manage_options',
			'wp-security-settings',
			array( $this, 'display_settings_page' )
		);
	}

	/**
	 * Display the main plugin page.
	 */
	public function display_main_page() {
		require_once WP_SECURITY_PLUGIN_DIR . 'admin/views/main-page.php';
	}

	/**
	 * Display the settings page.
	 */
	public function display_settings_page() {
		require_once WP_SECURITY_PLUGIN_DIR . 'admin/views/settings-page.php';
	}

	/**
	 * Register plugin settings.
	 */
	public function register_settings() {
		register_setting(
			'wp_security_settings',
			'wp_security_scan_frequency',
			array(
				'type'    => 'string',
				'default' => 'daily',
			)
		);

		register_setting(
			'wp_security_settings',
			'wp_security_email_notifications',
			array(
				'type'    => 'boolean',
				'default' => true,
			)
		);
	}

	/**
	 * Add action links to the plugins page.
	 *
	 * @param array $links Array of plugin action links.
	 * @return array Modified array of plugin action links.
	 */
	public function add_action_links( $links ) {
		$plugin_links = array(
			'<a href="' . admin_url( 'admin.php?page=wp-security-hardening' ) . '">' . __( 'Dashboard', 'wp-security-hardening' ) . '</a>',
			'<a href="' . admin_url( 'admin.php?page=wp-security-settings' ) . '">' . __( 'Settings', 'wp-security-hardening' ) . '</a>',
		);
		return array_merge( $plugin_links, $links );
	}
}
