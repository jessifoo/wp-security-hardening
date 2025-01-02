<?php
/**
 * WordPress Security Plugin Cron Manager
 *
 * Manages scheduled security tasks across multiple WordPress sites while
 * coordinating resource usage and maintaining shared API limits.
 *
 * @package WP_Security
 * @subpackage Scheduling
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

/**
 * Cron Manager Class
 *
 * Handles scheduling and execution of security tasks across multiple sites.
 * Coordinates with Site Network to ensure efficient resource usage.
 */
class WP_Security_Cron_Manager {
	/**
	 * Cron schedule intervals in seconds
	 */
	private const SCHEDULE_INTERVALS = array(
		'five_minutes'   => 300,
		'thirty_minutes' => 1800,
	);

	/**
	 * Cron task hooks
	 */
	private const TASK_HOOKS = array(
		'hourly_scan'   => 'wp_security_hourly_scan',
		'daily_cleanup' => 'wp_security_daily_cleanup',
		'weekly_report' => 'wp_security_weekly_report',
	);

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Logger instance
	 *
	 * @var WP_Security_Logger
	 */
	private $logger;

	/**
	 * Site Network instance
	 *
	 * @var WP_Security_Site_Network
	 */
	private $network;

	/**
	 * Scan hook
	 *
	 * @var string
	 */
	private $scan_hook = 'wp_security_scheduled_scan';

	/**
	 * Cleanup hook
	 *
	 * @var string
	 */
	private $cleanup_hook = 'wp_security_cleanup_logs';

	/**
	 * Plugin file path
	 *
	 * @var string
	 */
	private $plugin_file;

	/**
	 * Get singleton instance
	 *
	 * @return self Singleton instance
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor to prevent direct instantiation
	 *
	 * Initializes dependencies and registers WordPress hooks
	 */
	private function __construct() {
		$this->logger      = new WP_Security_Logger();
		$this->network     = WP_Security_Site_Network::get_instance();
		$this->plugin_file = dirname( __DIR__, 1 ) . '/wp-security-hardening.php';

		$this->register_cron_schedules();
		$this->register_task_handlers();
	}

	/**
	 * Initialize cron schedules and ensure tasks are scheduled
	 *
	 * @return void
	 */
	public function init(): void {
		try {
			$this->schedule_security_tasks();
			$this->logger->log( 'cron', 'Cron manager initialized successfully' );
		} catch ( Exception $e ) {
			$this->logger->log( 'error', 'Failed to initialize cron manager: ' . $e->getMessage() );
		}
	}

	/**
	 * Register custom cron schedules
	 *
	 * @return void
	 */
	private function register_cron_schedules(): void {
		add_filter( 'cron_schedules', array( $this, 'add_custom_schedules' ) );
	}

	/**
	 * Register handlers for cron tasks
	 *
	 * @return void
	 */
	private function register_task_handlers(): void {
		add_action( self::TASK_HOOKS['hourly_scan'], array( $this, 'run_hourly_scan' ) );
		add_action( self::TASK_HOOKS['daily_cleanup'], array( $this, 'run_daily_cleanup' ) );
		add_action( self::TASK_HOOKS['weekly_report'], array( $this, 'run_weekly_report' ) );
	}

	/**
	 * Add custom cron schedule intervals
	 *
	 * @param array<string, array<string, mixed>> $schedules Existing WordPress schedules
	 * @return array<string, array<string, mixed>> Modified schedules
	 */
	public function add_custom_schedules( array $schedules ): array {
		$schedules['wp_security_5min'] = array(
			'interval' => self::SCHEDULE_INTERVALS['five_minutes'],
			'display'  => 'Every 5 minutes',
		);

		$schedules['wp_security_30min'] = array(
			'interval' => self::SCHEDULE_INTERVALS['thirty_minutes'],
			'display'  => 'Every 30 minutes',
		);

		return $schedules;
	}

	/**
	 * Schedule all security tasks if not already scheduled
	 *
	 * @return void
	 * @throws Exception If scheduling fails
	 */
	private function schedule_security_tasks(): void {
		$tasks = array(
			self::TASK_HOOKS['hourly_scan']   => 'hourly',
			self::TASK_HOOKS['daily_cleanup'] => 'daily',
			self::TASK_HOOKS['weekly_report'] => 'weekly',
		);

		foreach ( $tasks as $hook => $recurrence ) {
			if ( ! wp_next_scheduled( $hook ) ) {
				$scheduled = wp_schedule_event( time(), $recurrence, $hook );
				if ( false === $scheduled ) {
					throw new Exception( "Failed to schedule task: {$hook}" );
				}
			}
		}
	}

	/**
	 * Activate all scheduled tasks
	 *
	 * @return void
	 */
	public function activate_schedules(): void {
		try {
			$this->schedule_security_tasks();
			$this->logger->log( 'cron', 'Activated security schedules' );
		} catch ( Exception $e ) {
			$this->logger->log( 'error', 'Failed to activate schedules: ' . $e->getMessage() );
		}
	}

	/**
	 * Deactivate all scheduled tasks
	 *
	 * @return void
	 */
	public function deactivate_schedules(): void {
		foreach ( self::TASK_HOOKS as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		$this->logger->log( 'cron', 'Deactivated security schedules' );
	}

	/**
	 * Run hourly security scan
	 *
	 * @return void
	 */
	public function run_hourly_scan(): void {
		try {
			if ( ! $this->is_scan_scheduled_for_site( get_current_blog_id() ) ) {
				$this->logger->log( 'cron', 'Skipping hourly scan - not scheduled for this site' );
				return;
			}

			$this->logger->log( 'cron', 'Starting hourly security scan' );
			$this->execute_hourly_scan_tasks();
			$this->logger->log( 'cron', 'Completed hourly security scan' );
		} catch ( Exception $e ) {
			$this->logger->log( 'error', 'Hourly scan failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Check if scan is scheduled for a site
	 *
	 * @param int $site_id Site ID to check
	 * @return bool Whether scan is scheduled
	 */
	public function is_scan_scheduled_for_site( $site_id ) {
		if ( is_multisite() ) {
			switch_to_blog( $site_id );
			$next_scan = wp_next_scheduled( $this->scan_hook );
			restore_current_blog();
			return (bool) $next_scan;
		}
		return (bool) wp_next_scheduled( $this->scan_hook );
	}

	/**
	 * Check if plugin is network active in multisite
	 *
	 * @return bool Whether plugin is network active
	 */
	public function is_network_active() {
		if ( ! is_multisite() ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . '/wp-admin/includes/plugin.php';
		}

		return is_plugin_active_for_network( plugin_basename( $this->plugin_file ) );
	}

	/**
	 * Execute hourly scan tasks
	 *
	 * @return void
	 * @throws Exception If task execution fails
	 */
	private function execute_hourly_scan_tasks(): void {
		global $wp_security_scanner, $wp_security_file_monitor;

		// File integrity checks
		$wp_security_file_monitor->check_core_files();

		// Malware scans
		$wp_security_scanner->quick_scan();

		// Update security rules
		do_action( 'wp_security_update_rules' );

		// Sync with network if needed
		if ( $this->is_network_active() ) {
			$this->network->sync_data( 'scans' );
		}
	}

	/**
	 * Run daily cleanup tasks
	 *
	 * @return void
	 */
	public function run_daily_cleanup(): void {
		try {
			$this->logger->log( 'cron', 'Starting daily cleanup' );
			$this->cleanup_old_logs();
			global $wp_security_quarantine;
			$wp_security_quarantine->cleanup_old_files();
			$this->cleanup_temp_files();
			do_action( 'wp_security_daily_report' );
			$this->logger->log( 'cron', 'Completed daily cleanup' );
		} catch ( Exception $e ) {
			$this->logger->log( 'error', 'Daily cleanup failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Clean up old log entries
	 *
	 * @return void
	 */
	public function cleanup_old_logs() {
		global $wpdb;

		// Keep logs for 30 days
		$cutoff = date( 'Y-m-d H:i:s', strtotime( '-30 days' ) );

		$table_name = $wpdb->prefix . 'security_logs';
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM $table_name WHERE log_time < %s",
				$cutoff
			)
		);

		$this->logger->log( 'info', 'Cleaned up old log entries' );
	}

	/**
	 * Clean up temporary files
	 *
	 * @return void
	 */
	private function cleanup_temp_files(): void {
		$temp_dir = WP_CONTENT_DIR . '/security-temp';

		if ( ! is_dir( $temp_dir ) ) {
			return;
		}

		$files = glob( $temp_dir . '/*' );
		$now   = time();

		foreach ( $files as $file ) {
			if ( is_file( $file ) ) {
				if ( $now - filemtime( $file ) >= 86400 ) {
					unlink( $file );
				}
			}
		}
	}

	/**
	 * Generate and send weekly security report
	 *
	 * @return void
	 */
	public function run_weekly_report(): void {
		try {
			$this->logger->log( 'cron', 'Generating weekly security report' );
			$report_data = $this->generate_weekly_report();
			$this->send_weekly_report( $report_data );
			$this->logger->log( 'cron', 'Weekly report sent successfully' );
		} catch ( Exception $e ) {
			$this->logger->log( 'error', 'Weekly report generation failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Generate weekly report data
	 *
	 * @return array<string, mixed> Report data
	 */
	private function generate_weekly_report(): array {
		// Collect weekly statistics
		return array(
			'scans_performed'  => get_option( 'wp_security_weekly_scans', 0 ),
			'threats_detected' => get_option( 'wp_security_weekly_threats', array() ),
			'blocked_ips'      => get_option( 'wp_security_weekly_blocks', array() ),
			'file_changes'     => get_option( 'wp_security_weekly_changes', array() ),
			'resource_usage'   => get_option( 'wp_security_weekly_resources', array() ),
		);
	}

	/**
	 * Send weekly report
	 *
	 * @param array<string, mixed> $report_data Report data
	 * @return void
	 */
	private function send_weekly_report( array $report_data ): void {
		// Use notification system to send report
		do_action( 'wp_security_notification', 'weekly_report', 'Weekly Security Report', $report_data );
	}
}
