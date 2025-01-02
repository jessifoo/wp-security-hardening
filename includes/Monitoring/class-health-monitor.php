<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Health_Monitor {
	private $metrics          = array();
	private $critical_issues  = array();
	private $warnings         = array();
	private $auto_fix_enabled = false;

	public function __construct() {
		// WordPress site health integration
		add_filter( 'site_status_tests', array( $this, 'register_site_health_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_information' ) );

		// Health check actions
		add_action( 'admin_init', array( $this, 'check_health' ) );
		add_action( 'wp_ajax_get_phpinfo', array( $this, 'get_phpinfo' ) );
		add_action( 'wp_ajax_auto_fix_issues', array( $this, 'auto_fix_issues' ) );

		// Schedule health checks
		if ( ! wp_next_scheduled( 'wp_security_health_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'wp_security_health_check' );
		}
		add_action( 'wp_security_health_check', array( $this, 'check_health' ) );

		// Auto-fix scheduler
		if ( ! wp_next_scheduled( 'wp_security_auto_fix' ) ) {
			wp_schedule_event( time(), 'twicedaily', 'wp_security_auto_fix' );
		}
		add_action( 'wp_security_auto_fix', array( $this, 'auto_fix_scheduled' ) );
	}

	/**
	 * Register tests with WordPress Site Health
	 */
	public function register_site_health_tests( $tests ) {
		$tests['direct']['wp_security_malware'] = array(
			'label' => __( 'Security Scan Status' ),
			'test'  => array( $this, 'site_health_malware_test' ),
		);

		$tests['direct']['wp_security_updates'] = array(
			'label' => __( 'Security Updates Status' ),
			'test'  => array( $this, 'site_health_updates_test' ),
		);

		$tests['direct']['wp_security_integrity'] = array(
			'label' => __( 'File Integrity Status' ),
			'test'  => array( $this, 'site_health_integrity_test' ),
		);

		return $tests;
	}

	/**
	 * Add debug information to WordPress Site Health
	 */
	public function add_debug_information( $info ) {
		$info['wp_security_health'] = array(
			'label'  => __( 'Security Health Status' ),
			'fields' => array(
				'last_scan'     => array(
					'label' => __( 'Last Security Scan' ),
					'value' => get_option( 'wp_security_last_scan', 'Never' ),
				),
				'threats_found' => array(
					'label' => __( 'Active Threats' ),
					'value' => count( $this->critical_issues ),
				),
				'auto_fixes'    => array(
					'label' => __( 'Auto-fixes Applied' ),
					'value' => get_option( 'wp_security_auto_fixes_count', 0 ),
				),
			),
		);
		return $info;
	}

	/**
	 * Automatically fix issues that can be resolved
	 */
	public function auto_fix_scheduled() {
		$fixed_count = 0;

		// Get current issues
		$critical_issues = get_option( 'wp_security_critical_issues', array() );
		$warnings        = get_option( 'wp_security_warnings', array() );

		foreach ( $critical_issues as $key => $issue ) {
			if ( ! empty( $issue['auto_fixable'] ) && $this->fix_issue( $issue )['success'] ) {
				unset( $critical_issues[ $key ] );
				++$fixed_count;
			}
		}

		foreach ( $warnings as $key => $warning ) {
			if ( ! empty( $warning['auto_fixable'] ) && $this->fix_issue( $warning )['success'] ) {
				unset( $warnings[ $key ] );
				++$fixed_count;
			}
		}

		// Update issues lists
		update_option( 'wp_security_critical_issues', $critical_issues );
		update_option( 'wp_security_warnings', $warnings );

		// Update fix count
		$total_fixes = get_option( 'wp_security_auto_fixes_count', 0 ) + $fixed_count;
		update_option( 'wp_security_auto_fixes_count', $total_fixes );

		// Log results
		if ( $fixed_count > 0 ) {
			error_log( sprintf( 'WP Security: Auto-fixed %d issues', $fixed_count ) );
		}
	}

	public function check_health() {
		$this->metrics         = array();
		$this->critical_issues = array();
		$this->warnings        = array();

		// System Metrics
		$this->check_system_metrics();

		// WordPress Health
		$this->check_wordpress_health();

		// Database Health
		$this->check_database_health();

		// Security Metrics
		$this->check_security_metrics();

		// Save results
		update_option( 'wp_security_health_metrics', $this->metrics );
		update_option( 'wp_security_critical_issues', $this->critical_issues );
		update_option( 'wp_security_warnings', $this->warnings );
	}

	private function check_system_metrics() {
		// Memory Usage
		$memory_limit            = ini_get( 'memory_limit' );
		$memory_usage            = memory_get_usage( true );
		$this->metrics['memory'] = array(
			'limit'   => $this->convert_to_bytes( $memory_limit ),
			'usage'   => $memory_usage,
			'percent' => ( $memory_usage / $this->convert_to_bytes( $memory_limit ) ) * 100,
		);

		if ( $this->metrics['memory']['percent'] > 80 ) {
			$this->warnings[] = array(
				'type'         => 'memory',
				'message'      => 'Memory usage is above 80%',
				'auto_fixable' => false,
			);
		}

		// PHP Version
		$php_version                  = phpversion();
		$this->metrics['php_version'] = $php_version;
		if ( version_compare( $php_version, '7.4', '<' ) ) {
			$this->critical_issues[] = array(
				'type'         => 'php_version',
				'message'      => 'PHP version is below 7.4',
				'auto_fixable' => false,
			);
		}

		// Disk Space
		$disk_free_space       = disk_free_space( ABSPATH );
		$disk_total_space      = disk_total_space( ABSPATH );
		$this->metrics['disk'] = array(
			'free'         => $disk_free_space,
			'total'        => $disk_total_space,
			'percent_used' => ( ( $disk_total_space - $disk_free_space ) / $disk_total_space ) * 100,
		);

		if ( $this->metrics['disk']['percent_used'] > 90 ) {
			$this->critical_issues[] = array(
				'type'         => 'disk_space',
				'message'      => 'Disk usage is above 90%',
				'auto_fixable' => true,
			);
		}

		// Max Execution Time
		$max_execution                       = ini_get( 'max_execution_time' );
		$this->metrics['max_execution_time'] = $max_execution;
		if ( $max_execution < 30 ) {
			$this->warnings[] = array(
				'type'         => 'execution_time',
				'message'      => 'Max execution time is too low',
				'auto_fixable' => true,
			);
		}

		// PHP Resolver Configuration
		$resolver_config                  = php_ini_loaded_file();
		$this->metrics['resolver_config'] = array(
			'loaded_file' => $resolver_config,
			'extensions'  => get_loaded_extensions(),
		);

		// Check for resolver extension issues
		$required_extensions = array( 'curl', 'json', 'mysqli', 'openssl', 'zip' );
		$missing_extensions  = array();

		foreach ( $required_extensions as $ext ) {
			if ( ! extension_loaded( $ext ) ) {
				$missing_extensions[] = $ext;
			}
		}

		if ( ! empty( $missing_extensions ) ) {
			$this->warnings[] = array(
				'type'         => 'php_resolver',
				'message'      => 'Missing required PHP extensions: ' . implode( ', ', $missing_extensions ),
				'auto_fixable' => true,
				'data'         => array(
					'missing_extensions' => $missing_extensions,
				),
			);
		}
	}

	private function check_wordpress_health() {
		global $wp_version;

		// WordPress Version
		$this->metrics['wp_version'] = $wp_version;
		if ( version_compare( $wp_version, get_site_transient( 'update_core' )->version_checked, '<' ) ) {
			$this->warnings[] = array(
				'type'         => 'wp_version',
				'message'      => 'WordPress needs updating',
				'auto_fixable' => false,
			);
		}

		// Plugin Updates
		$plugin_updates                       = get_plugin_updates();
		$this->metrics['plugins_need_update'] = count( $plugin_updates );
		if ( ! empty( $plugin_updates ) ) {
			$this->warnings[] = array(
				'type'         => 'plugin_updates',
				'message'      => count( $plugin_updates ) . ' plugins need updating',
				'auto_fixable' => true,
			);
		}

		// Debug Mode
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$this->warnings[] = array(
				'type'         => 'debug_mode',
				'message'      => 'Debug mode is enabled',
				'auto_fixable' => true,
			);
		}

		// File Permissions
		$this->check_file_permissions();
	}

	private function check_database_health() {
		global $wpdb;

		// Database Size
		$db_size                        = $wpdb->get_row( "SELECT SUM(data_length + index_length) as size FROM information_schema.TABLES WHERE table_schema = '" . DB_NAME . "'" );
		$this->metrics['database_size'] = $db_size->size;

		// Table Optimization
		$tables_status            = $wpdb->get_results( 'SHOW TABLE STATUS' );
		$tables_need_optimization = 0;
		foreach ( $tables_status as $table ) {
			if ( $table->Data_free > 0 ) {
				++$tables_need_optimization;
			}
		}

		if ( $tables_need_optimization > 0 ) {
			$this->warnings[] = array(
				'type'         => 'database_optimization',
				'message'      => $tables_need_optimization . ' tables need optimization',
				'auto_fixable' => true,
			);
		}

		// Auto-loaded Options
		$autoload_size                  = $wpdb->get_var( "SELECT SUM(LENGTH(option_value)) FROM $wpdb->options WHERE autoload = 'yes'" );
		$this->metrics['autoload_size'] = $autoload_size;

		if ( $autoload_size > 1000000 ) { // 1MB
			$this->warnings[] = array(
				'type'         => 'autoload_options',
				'message'      => 'Autoloaded options exceed 1MB',
				'auto_fixable' => true,
			);
		}
	}

	private function check_security_metrics() {
		// File Changes
		$file_changes                      = get_option( 'wp_security_file_changes', array() );
		$this->metrics['suspicious_files'] = count( $file_changes );

		if ( ! empty( $file_changes ) ) {
			$this->critical_issues[] = array(
				'type'         => 'file_changes',
				'message'      => count( $file_changes ) . ' suspicious file changes detected',
				'auto_fixable' => false,
			);
		}

		// Failed Logins
		$failed_logins                      = $this->get_failed_logins_last_24h();
		$this->metrics['failed_logins_24h'] = $failed_logins;

		if ( $failed_logins > 50 ) {
			$this->warnings[] = array(
				'type'         => 'failed_logins',
				'message'      => 'High number of failed login attempts',
				'auto_fixable' => false,
			);
		}

		// SSL
		if ( ! is_ssl() ) {
			$this->critical_issues[] = array(
				'type'         => 'ssl',
				'message'      => 'SSL is not enabled',
				'auto_fixable' => false,
			);
		}
	}

	private function check_file_permissions() {
		$files_to_check = array(
			ABSPATH . 'wp-config.php'   => '0400',
			ABSPATH . '.htaccess'       => '0644',
			WP_CONTENT_DIR              => '0755',
			WP_CONTENT_DIR . '/themes'  => '0755',
			WP_CONTENT_DIR . '/plugins' => '0755',
		);

		foreach ( $files_to_check as $file => $required_perms ) {
			if ( file_exists( $file ) ) {
				$current_perms = substr( sprintf( '%o', fileperms( $file ) ), -4 );
				if ( $current_perms != $required_perms ) {
					$this->warnings[] = array(
						'type'         => 'file_permissions',
						'message'      => "Incorrect permissions on {$file}",
						'auto_fixable' => true,
						'data'         => array(
							'file'     => $file,
							'current'  => $current_perms,
							'required' => $required_perms,
						),
					);
				}
			}
		}
	}

	public function get_phpinfo() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized' );
		}

		ob_start();
		phpinfo();
		$phpinfo = ob_get_clean();

		// Convert to more readable format
		$phpinfo = preg_replace( '%^.*<body>(.*)</body>.*$%ms', '$1', $phpinfo );
		$phpinfo = str_replace( '<table>', '<table class="widefat">', $phpinfo );

		wp_send_json_success( array( 'phpinfo' => $phpinfo ) );
	}

	public function auto_fix_issues() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized' );
		}

		check_ajax_referer( 'wp_security_auto_fix' );

		$fixed  = array();
		$failed = array();

		// Get issues that can be auto-fixed
		$issues = array_merge(
			array_filter(
				$this->critical_issues,
				function ( $issue ) {
					return $issue['auto_fixable'];
				}
			),
			array_filter(
				$this->warnings,
				function ( $issue ) {
					return $issue['auto_fixable'];
				}
			)
		);

		foreach ( $issues as $issue ) {
			$result = $this->fix_issue( $issue );
			if ( $result['success'] ) {
				$fixed[] = $issue['type'];
			} else {
				$failed[] = array(
					'type'  => $issue['type'],
					'error' => $result['error'],
				);
			}
		}

		// Recheck health after fixes
		$this->check_health();

		wp_send_json_success(
			array(
				'fixed'       => $fixed,
				'failed'      => $failed,
				'new_metrics' => $this->metrics,
			)
		);
	}

	private function fix_issue( $issue ) {
		switch ( $issue['type'] ) {
			case 'disk_space':
				return $this->clean_disk_space();

			case 'execution_time':
				return $this->increase_execution_time();

			case 'plugin_updates':
				return $this->update_plugins();

			case 'debug_mode':
				return $this->disable_debug_mode();

			case 'database_optimization':
				return $this->optimize_database();

			case 'autoload_options':
				return $this->optimize_autoload_options();

			case 'file_permissions':
				return $this->fix_file_permissions( $issue['data'] );

			case 'php_resolver':
				return $this->fix_php_resolver( $issue['data'] );

			default:
				return array(
					'success' => false,
					'error'   => 'Unknown issue type',
				);
		}
	}

	/**
	 * Clean up disk space by removing post revisions and expired data.
	 *
	 * @return array Result of the cleanup operation.
	 */
	private function clean_disk_space() {
		global $wpdb;

		// Clean up post revisions.
		$revisions = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID FROM $wpdb->posts WHERE post_type = %s",
				'revision'
			)
		);

		foreach ( $revisions as $revision ) {
			wp_delete_post( $revision->ID, true );
		}

		// Clean up transients.
		$this->delete_expired_transients();

		// Clean up logs.
		$this->cleanup_logs();

		return array( 'success' => true );
	}

	private function increase_execution_time() {
		if ( @ini_set( 'max_execution_time', '300' ) ) {
			return array( 'success' => true );
		}
		return array(
			'success' => false,
			'error'   => 'Could not increase execution time',
		);
	}

	private function update_plugins() {
		include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		include_once ABSPATH . 'wp-admin/includes/update.php';

		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$plugins  = get_plugin_updates();

		$results = array();
		foreach ( $plugins as $plugin ) {
			$result = $upgrader->upgrade( $plugin->update->plugin );
			if ( $result ) {
				$results[] = $plugin->update->plugin;
			}
		}

		return array(
			'success' => ! empty( $results ),
			'updated' => $results,
		);
	}

	private function disable_debug_mode() {
		$config_file = ABSPATH . 'wp-config.php';
		$config      = file_get_contents( $config_file );

		$config = preg_replace(
			"/define\(\s*'WP_DEBUG',\s*true\s*\);/",
			"define('WP_DEBUG', false);",
			$config
		);

		if ( file_put_contents( $config_file, $config ) ) {
			return array( 'success' => true );
		}

		return array(
			'success' => false,
			'error'   => 'Could not modify wp-config.php',
		);
	}

	private function optimize_database() {
		global $wpdb;

		$tables = $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );
		foreach ( $tables as $table ) {
			$table_name = array_values( get_object_vars( $table ) )[0];
			$wpdb->query( "OPTIMIZE TABLE $table_name" );
		}

		return array( 'success' => true );
	}

	private function optimize_autoload_options() {
		global $wpdb;

		// Get large autoloaded options
		$large_options = $wpdb->get_results(
			"SELECT option_name, LENGTH(option_value) as size 
             FROM $wpdb->options 
             WHERE autoload = 'yes' 
             AND LENGTH(option_value) > 10000"
		);

		foreach ( $large_options as $option ) {
			$wpdb->update(
				$wpdb->options,
				array( 'autoload' => 'no' ),
				array( 'option_name' => $option->option_name )
			);
		}

		return array( 'success' => true );
	}

	private function fix_file_permissions( $data ) {
		if ( chmod( $data['file'], octdec( $data['required'] ) ) ) {
			return array( 'success' => true );
		}
		return array(
			'success' => false,
			'error'   => 'Could not change file permissions',
		);
	}

	private function fix_php_resolver( $data ) {
		if ( ! isset( $data['missing_extensions'] ) || empty( $data['missing_extensions'] ) ) {
			return array(
				'success' => false,
				'error'   => 'No missing extensions specified',
			);
		}

		$success = true;
		$errors  = array();
		$fixed   = array();

		foreach ( $data['missing_extensions'] as $ext ) {
			try {
				// First try to enable the extension if it exists but is disabled
				$ini_file       = php_ini_loaded_file();
				$extension_line = "extension={$ext}.so";

				if ( is_writable( $ini_file ) ) {
					$current_content = file_get_contents( $ini_file );

					// Check if extension line exists but is commented out
					if ( strpos( $current_content, ";{$extension_line}" ) !== false ) {
						$new_content = str_replace( ";{$extension_line}", $extension_line, $current_content );
						file_put_contents( $ini_file, $new_content );
						$fixed[] = $ext;
					} elseif ( strpos( $current_content, $extension_line ) === false ) {
						// Add extension if not present
						file_put_contents( $ini_file, $current_content . "\n" . $extension_line );
						$fixed[] = $ext;
					}
				} else {
					$errors[] = "Cannot write to php.ini file for extension: {$ext}";
					$success  = false;
				}
			} catch ( Exception $e ) {
				$errors[] = "Error enabling extension {$ext}: " . $e->getMessage();
				$success  = false;
			}
		}

		// Log the changes
		if ( ! empty( $fixed ) ) {
			error_log(
				sprintf(
					'WP Security: Fixed PHP resolver configuration for extensions: %s',
					implode( ', ', $fixed )
				)
			);
		}

		return array(
			'success' => $success,
			'fixed'   => $fixed,
			'errors'  => $errors,
		);
	}

	private function delete_expired_transients() {
		global $wpdb;

		$wpdb->query(
			"DELETE a, b FROM $wpdb->options a, $wpdb->options b
            WHERE a.option_name LIKE '%_transient_%'
            AND a.option_name NOT LIKE '%_transient_timeout_%'
            AND b.option_name = CONCAT(
                '_transient_timeout_',
                SUBSTRING(
                    a.option_name,
                    CHAR_LENGTH('_transient_') + 1
                )
            )
            AND b.option_value < UNIX_TIMESTAMP()"
		);
	}

	private function cleanup_logs() {
		$log_files = glob( ABSPATH . 'wp-content/debug.log' );
		foreach ( $log_files as $file ) {
			if ( filesize( $file ) > 1000000 ) { // 1MB
				unlink( $file );
			}
		}
	}

	private function get_failed_logins_last_24h() {
		global $wpdb;

		$count = $wpdb->get_var(
			"SELECT COUNT(*) FROM $wpdb->options 
             WHERE option_name LIKE '_transient_failed_login_%'"
		);

		return $count;
	}

	private function convert_to_bytes( $value ) {
		$value = trim( $value );
		$last  = strtolower( $value[ strlen( $value ) - 1 ] );
		$value = (int) $value;

		switch ( $last ) {
			case 'g':
				$value *= 1024;
			case 'm':
				$value *= 1024;
			case 'k':
				$value *= 1024;
		}

		return $value;
	}

	public function get_metrics_for_display() {
		return array(
			'system'    => array(
				'memory_usage'   => $this->format_memory( $this->metrics['memory']['usage'] ),
				'memory_limit'   => $this->format_memory( $this->metrics['memory']['limit'] ),
				'memory_percent' => round( $this->metrics['memory']['percent'], 2 ),
				'disk_free'      => $this->format_bytes( $this->metrics['disk']['free'] ),
				'disk_total'     => $this->format_bytes( $this->metrics['disk']['total'] ),
				'disk_percent'   => round( $this->metrics['disk']['percent_used'], 2 ),
				'php_version'    => $this->metrics['php_version'],
			),
			'wordpress' => array(
				'version'             => $this->metrics['wp_version'],
				'plugins_need_update' => $this->metrics['plugins_need_update'],
				'debug_mode'          => defined( 'WP_DEBUG' ) && WP_DEBUG,
			),
			'database'  => array(
				'size'          => $this->format_bytes( $this->metrics['database_size'] ),
				'autoload_size' => $this->format_bytes( $this->metrics['autoload_size'] ),
			),
			'security'  => array(
				'suspicious_files'  => $this->metrics['suspicious_files'],
				'failed_logins_24h' => $this->metrics['failed_logins_24h'],
				'ssl_enabled'       => is_ssl(),
			),
		);
	}

	private function format_bytes( $bytes ) {
		$units  = array( 'B', 'KB', 'MB', 'GB', 'TB' );
		$bytes  = max( $bytes, 0 );
		$pow    = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
		$pow    = min( $pow, count( $units ) - 1 );
		$bytes /= pow( 1024, $pow );
		return round( $bytes, 2 ) . ' ' . $units[ $pow ];
	}

	private function format_memory( $bytes ) {
		return $this->format_bytes( $bytes );
	}
}
