<?php

namespace WP_Security;

// Group WordPress core function imports
use function add_action;
use function add_filter;
use function admin_url;
use function dirname;
use function esc_html;
use function esc_html__;
use function esc_url;
use function flush_rewrite_rules;
use function is_null;
use function load_plugin_textdomain;
use function plugin_basename;
use function plugin_dir_path;
use function plugin_dir_url;
use function register_activation_hook;
use function register_deactivation_hook;
use function sprintf;
use function time;
use function wp_next_scheduled;
use function wp_schedule_event;

// Class imports
use Exception;
use WP_Security\Container;
use WP_Security\Utils\Logger;
use WP_Security\Security\QuarantineManager;
use WP_Security\Security\Scanner\Scanner;
use WP_Security\Events\EventDispatcher;
use WP_Security\Security\RateLimiter;
use WP_Security\Security\Scanner\ScanManager;
use WP_Security\Admin\WP_Security_Hardening_Admin;

/**
 * Plugin Name: WordPress Security Hardening
 * Plugin URI: https://github.com/your-username/wp-security-hardening
 * Description: A comprehensive security plugin that hardens WordPress installations, prevents malware, and detects threats.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 8.2
 * Author: Jessica Johnson
 * Author URI: https://jessica-johnson.ca
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-security-hardening
 * Domain Path: /languages
 *
 * @package WP_Security_Hardening
 */

// If this file is called directly, abort.
if (! defined('ABSPATH')) {
	exit('Direct access not permitted.');
}

if (!defined('DAY_IN_SECONDS')) {
	define('DAY_IN_SECONDS', 86400);
}

// Simplify required files - only include essential WordPress files
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-includes/pluggable.php';

// Consolidate constants
define(
	'WP_SECURITY',
	array(
		'VERSION'  => '1.0.0',
		'DIR'      => plugin_dir_path(__FILE__),
		'URL'      => plugin_dir_url(__FILE__),
		'BASENAME' => plugin_basename(__FILE__),
	)
);

// Ensure autoloader exists and load it
$autoloader_path = WP_SECURITY['DIR'] . 'includes/class-autoloader.php';
if (! file_exists($autoloader_path)) {
	add_action(
		'admin_notices',
		function () {
			echo '<div class="error"><p>' . esc_html__(
				'WordPress Security Hardening autoloader not found. Plugin cannot initialize.',
				'wp-security-hardening'
			) . '</p></div>';
		}
	);
	return;
}

require_once $autoloader_path;
Autoloader::register(); // Updated to use namespaced autoloader class

/**
 * The main plugin class.
 */
class WP_Security_Hardening {
	/** @var WP_Security_Hardening Single instance */
	private static $instance = null;

	/** @var array Plugin components */
	private $components = array();

	/** @var WP_Security\Container Container instance */
	private $container;

	/**
	 * Main plugin instance.
	 *
	 * @return self
	 */
	public static function instance(): self {
		if (is_null(self::$instance)) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->container = new Container();
		$this->registerServices();
		$this->initializePlugin();
	}

	/**
	 * Initialize plugin with basic functionality.
	 */
	private function initializePlugin() {
		try {
			if (!isset($this->components['scanner'])) {
				$this->components['scanner'] = new Scanner(
					$this->container->get('logger'),
					$this->container->get('quarantine_manager')
				);
			}

			// Schedule daily scan
			if (!wp_next_scheduled('wp_security_daily_scan')) {
				wp_schedule_event(time(), 'daily', 'wp_security_daily_scan');
			}
			add_action('wp_security_daily_scan', array($this->components['scanner'], 'run_scan'));
		} catch (Exception $e) {
			add_action('admin_notices', function () use ($e) {
				echo '<div class="error"><p>Security plugin error: ' . esc_html($e->getMessage()) . '</p></div>';
			});
		}
	}

	/**
	 * Register services.
	 */
	private function registerServices() {
		$this->container->register(
			'logger',
			function () {
				return new Logger();
			}
		);

		$this->container->register(
			'event_dispatcher',
			function ($container) {
				return new EventDispatcher($container->get('logger'));
			}
		);

		$this->container->register(
			'rate_limiter',
			function () {
				return new RateLimiter();
			}
		);

		$this->container->register(
			'quarantine_manager',
			function () {
				return new QuarantineManager();
			}
		);

		$this->container->register(
			'scanner',
			function ($container) {
				return new ScanManager(
					$container->get('rate_limiter'),
					$container->get('event_dispatcher'),
					$container->get('quarantine_manager')
				);
			}
		);
	}

	/**
	 * Register event listeners.
	 */
	private function registerEventListeners() {
		$dispatcher = $this->container->get('event_dispatcher');

		// Register core security event listeners
		$dispatcher->addListener(
			'security.threat_detected',
			function ($threat) {
				// Handle threat detection
				$this->container->get('logger')->warning('Security threat detected', $threat);
			}
		);

		$dispatcher->addListener(
			'security.scan_complete',
			function ($results) {
				// Handle scan completion
				$this->container->get('logger')->info('Security scan completed', $results);
			}
		);
	}

	/**
	 * Initialize admin components.
	 */
	private function initializeAdmin() {
		$this->components['admin'] = new WP_Security_Hardening_Admin();
		add_filter('plugin_action_links_' . WP_SECURITY['BASENAME'], array($this, 'add_action_links'));
	}

	/**
	 * Initialize schedules.
	 */
	private function initializeSchedules(): void {
		$schedules = array(
			'wp_security_scan'    => array(
				'interval' => DAY_IN_SECONDS,
				'callback' => array($this->components['scanner'], 'run_scan'),
			),
			'wp_security_cleanup' => array(
				'interval' => DAY_IN_SECONDS,
				'callback' => array($this->components['scanner'], 'cleanup'),
			),
		);

		foreach ($schedules as $hook => $schedule) {
			if (! wp_next_scheduled($hook)) {
				wp_schedule_event(time(), 'daily', $hook);
				add_action($hook, $schedule['callback']);
			}
		}
	}

	/**
	 * Initialize hooks.
	 */
	private function initializeHooks() {
		// Load translations
		add_action('init', array($this, 'load_plugin_textdomain'));
	}

	/**
	 * Load translations.
	 *
	 * @return void
	 */
	public function load_plugin_textdomain(): void {
		load_plugin_textdomain(
			'wp-security-hardening',
			false,
			dirname(plugin_basename(__FILE__)) . '/languages'
		);
	}

	/**
	 * Add action links.
	 *
	 * @param array $links Plugin action links
	 * @return array
	 */
	public function add_action_links(array $links): array {
		$plugin_links = array(
			'<a href="' . esc_url(admin_url('admin.php?page=wp-security-dashboard')) . '">' .
				esc_html__('Dashboard', 'wp-security-hardening') . '</a>',
			'<a href="' . esc_url(admin_url('admin.php?page=wp-security-hardening')) . '">' .
				esc_html__('Settings', 'wp-security-hardening') . '</a>',
		);
		return array_merge($plugin_links, $links);
	}

	/**
	 * Get a plugin component.
	 *
	 * @param string $component Component name
	 * @return object|null
	 */
	public function get_component(string $component): ?object {
		return isset($this->components[$component]) ? $this->components[$component] : null;
	}
}

/**
 * Returns the main instance of WP_Security_Hardening.
 *
 * @return WP_Security_Hardening
 */
function wp_security_hardening() {
	return WP_Security_Hardening::instance();
}

// Initialize plugin
add_action('plugins_loaded', __NAMESPACE__ . '\wp_security_hardening');

// Register activation/deactivation hooks with proper namespacing
register_activation_hook(
	__FILE__,
	function () {
		require_once WP_SECURITY['DIR'] . 'includes/class-activator.php';
		Activator::activate();

		require_once WP_SECURITY['DIR'] . 'includes/schema/resource-tables.php';
		Schema\ResourceTables::create_tables();

		flush_rewrite_rules();
	}
);

register_deactivation_hook(
	__FILE__,
	function () {
		require_once WP_SECURITY['DIR'] . 'includes/class-deactivator.php';
		Deactivator::deactivate();
	}
);
