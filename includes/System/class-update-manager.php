<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Update_Manager {
	private $core_repair;
	private $plugin_repair;
	private $rate_limiter;
	private $logger;
	private $quarantine;
	private $notifications;
	private $threat_intel;
	private $last_check_option = 'wp_security_last_update_check';
	private $actions_taken     = array();

	public function __construct() {
		require_once __DIR__ . '/class-core-repair.php';
		require_once __DIR__ . '/class-plugin-repair.php';
		require_once __DIR__ . '/class-rate-limiter.php';
		require_once __DIR__ . '/class-logger.php';
		require_once __DIR__ . '/class-quarantine-manager.php';
		require_once __DIR__ . '/class-notifications.php';
		require_once __DIR__ . '/class-threat-intelligence.php';

		$this->core_repair   = new WP_Security_Core_Repair();
		$this->plugin_repair = new WP_Security_Plugin_Repair();
		$this->rate_limiter  = new WP_Security_Rate_Limiter();
		$this->logger        = new WP_Security_Logger();
		$this->quarantine    = new WP_Security_Quarantine_Manager();
		$this->notifications = new WP_Security_Notifications();
		$this->threat_intel  = new WP_Security_Threat_Intelligence();

		// Check for updates every 6 hours
		add_action( 'wp_security_update_check', array( $this, 'check_all_updates' ) );
		if ( ! wp_next_scheduled( 'wp_security_update_check' ) ) {
			wp_schedule_event( time(), 'sixhours', 'wp_security_update_check' );
		}

		// Auto-remediation hooks
		add_action( 'wp_security_malware_detected', array( $this, 'handle_malware' ) );
		add_action( 'wp_security_core_modified', array( $this, 'handle_core_modification' ) );
		add_action( 'wp_security_plugin_compromised', array( $this, 'handle_plugin_compromise' ) );
		add_action( 'wp_security_suspicious_user', array( $this, 'handle_suspicious_user' ) );

		// Add manual update trigger for testing
		add_action( 'admin_post_force_security_updates', array( $this, 'force_updates' ) );
	}

	public function check_all_updates() {
		// Skip if checked recently (within last hour)
		$last_check = get_option( $this->last_check_option, 0 );
		if ( ( time() - $last_check ) < HOUR_IN_SECONDS ) {
			return;
		}

		// Check WordPress core
		$this->check_core_updates();

		// Check plugins if core is up to date
		if ( $this->is_core_healthy() ) {
			$this->check_plugin_updates();
		}

		update_option( $this->last_check_option, time() );
	}

	// Auto-remediation methods
	public function handle_malware( $data ) {
		$this->actions_taken[] = array(
			'type'    => 'malware',
			'time'    => current_time( 'mysql' ),
			'file'    => $data['file'],
			'actions' => array(),
		);

		// 1. Quarantine the file
		$quarantine_result = $this->quarantine->quarantine_file( $data['file'] );
		$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'quarantine';

		// 2. Try to clean the file
		if ( $this->clean_malware( $data ) ) {
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'cleaned';
		}

		// 3. If cleaning failed, restore from core/plugin source
		if ( file_exists( $data['file'] ) && $this->is_file_compromised( $data['file'] ) ) {
			$this->restore_original_file( $data['file'] );
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'restored';
		}

		$this->log_action( 'malware_remediation', $data['file'] );
	}

	public function handle_core_modification( $file ) {
		$this->actions_taken[] = array(
			'type'    => 'core',
			'time'    => current_time( 'mysql' ),
			'file'    => $file,
			'actions' => array(),
		);

		if ( ! $this->verify_core_checksum( $file ) ) {
			return;
		}

		// Restore the core file
		if ( $this->restore_core_file( $file ) ) {
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'restored';
			$this->log_action( 'core_remediation', $file );

			// Verify core files after restoration
			$this->verify_core_files();
		}
	}

	public function handle_plugin_compromise( $data ) {
		$this->actions_taken[] = array(
			'type'    => 'plugin',
			'time'    => current_time( 'mysql' ),
			'plugin'  => $data['plugin'],
			'actions' => array(),
		);

		// 1. Deactivate compromised plugin
		deactivate_plugins( $data['plugin'] );
		$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'deactivated';

		// 2. Download fresh copy from WordPress.org
		if ( $this->update_plugin( $data['plugin'] ) ) {
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'restored';
			activate_plugin( $data['plugin'] );
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'reactivated';
		}

		$this->log_action( 'plugin_remediation', $data['plugin'] );
	}

	public function handle_suspicious_user( $user_id ) {
		$this->actions_taken[] = array(
			'type'    => 'user',
			'time'    => current_time( 'mysql' ),
			'user_id' => $user_id,
			'actions' => array(),
		);

		// 1. Reset user password
		$random_password = wp_generate_password( 24, true, true );
		wp_set_password( $random_password, $user_id );
		$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'password_reset';

		// 2. Remove suspicious capabilities
		$user = get_user_by( 'id', $user_id );
		if ( $user ) {
			$this->remove_suspicious_capabilities( $user );
			$this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'][] = 'capabilities_cleaned';
		}

		// 3. Notify admin
		$user_data = get_userdata( $user_id );
		$this->notifications->send_notification(
			'suspicious_user',
			array(
				'user_login' => $user_data->user_login,
				'user_email' => $user_data->user_email,
				'actions'    => $this->actions_taken[ count( $this->actions_taken ) - 1 ]['actions'],
			)
		);

		$this->log_action( 'user_remediation', $user_data->user_login );
	}

	private function clean_malware( $data ) {
		if ( ! isset( $data['file'] ) || ! file_exists( $data['file'] ) ) {
			return false;
		}

		// Get file content
		$content = file_get_contents( $data['file'] );
		if ( $content === false ) {
			return false;
		}

		// Clean known malware patterns
		$cleaned_content = $this->threat_intel->clean_malicious_code( $content );
		if ( $cleaned_content === $content ) {
			return false;
		}

		// Backup original file
		$backup_path = $this->quarantine->get_quarantine_path( $data['file'] );
		if ( ! copy( $data['file'], $backup_path ) ) {
			return false;
		}

		// Write cleaned content
		if ( file_put_contents( $data['file'], $cleaned_content ) === false ) {
			// Restore from backup if write fails
			copy( $backup_path, $data['file'] );
			return false;
		}

		return true;
	}

	private function is_file_compromised( $file ) {
		$content = file_get_contents( $file );
		return $content && $this->threat_intel->contains_malicious_code( $content );
	}

	private function restore_original_file( $file ) {
		if ( strpos( $file, WP_PLUGIN_DIR ) === 0 ) {
			return $this->update_plugin( plugin_basename( $file ) );
		} elseif ( strpos( $file, ABSPATH ) === 0 ) {
			return $this->restore_core_file( $file );
		}
		return false;
	}

	private function remove_suspicious_capabilities( $user ) {
		$suspicious_caps = array(
			'edit_files',
			'edit_plugins',
			'edit_themes',
			'update_plugins',
			'update_themes',
			'update_core',
		);

		foreach ( $suspicious_caps as $cap ) {
			$user->remove_cap( $cap );
		}
	}

	private function log_action( $type, $target ) {
		$this->logger->log(
			$type,
			sprintf( 'Auto-remediation for %s: %s', $type, $target ),
			'info',
			array(
				'target'  => $target,
				'actions' => end( $this->actions_taken )['actions'],
			)
		);
	}

	private function check_core_updates() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		wp_version_check(); // Check for core updates

		$core = get_site_transient( 'update_core' );
		if ( empty( $core->updates ) ) {
			return;
		}

		foreach ( $core->updates as $update ) {
			if ( $update->response === 'upgrade' && version_compare( get_bloginfo( 'version' ), $update->current, '<' ) ) {
				// Log the update
				$this->logger->log( 'core_update', "Updating WordPress core to version {$update->current}" );

				// Perform the update
				if ( $this->update_wordpress_core( $update ) ) {
					$this->logger->log( 'core_update', "Successfully updated to {$update->current}" );

					// Verify core files after update
					$this->verify_core_files();
				} else {
					$this->logger->log( 'core_update', "Failed to update to {$update->current}", 'error' );
				}
				break;
			}
		}
	}

	private function update_wordpress_core( $update ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';

		// Backup current version
		$this->backup_core_files();

		// Perform update
		$upgrader = new Core_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $update );

		if ( is_wp_error( $result ) ) {
			$this->restore_core_backup();
			return false;
		}

		return true;
	}

	private function check_plugin_updates() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		wp_update_plugins(); // Check for plugin updates

		$plugins = get_site_transient( 'update_plugins' );
		if ( empty( $plugins->response ) ) {
			return;
		}

		foreach ( $plugins->response as $plugin_file => $plugin_data ) {
			// Check if we can make API calls
			if ( ! $this->rate_limiter->can_call( 'wordpress_api', 'hourly' ) ) {
				$this->logger->log( 'plugin_update', 'API rate limit reached, postponing updates' );
				break;
			}

			$this->logger->log( 'plugin_update', "Updating plugin: {$plugin_file}" );

			if ( $this->update_plugin( $plugin_file, $plugin_data ) ) {
				$this->logger->log( 'plugin_update', "Successfully updated {$plugin_file}" );

				// Verify plugin files after update
				$this->plugin_repair->check_plugin( $plugin_file, get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file ) );
			} else {
				$this->logger->log( 'plugin_update', "Failed to update {$plugin_file}", 'error' );
			}

			$this->rate_limiter->record_call( 'wordpress_api', 'hourly' );
		}
	}

	private function update_plugin( $plugin_file, $plugin_data ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';

		// Backup current version
		$this->backup_plugin( $plugin_file );

		// Perform update
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $plugin_file );

		if ( is_wp_error( $result ) ) {
			$this->restore_plugin_backup( $plugin_file );
			return false;
		}

		return true;
	}

	private function backup_core_files() {
		$backup_dir = WP_CONTENT_DIR . '/security-backups/core/' . date( 'Y-m-d-H-i-s' );
		wp_mkdir_p( $backup_dir );

		$core_files = $this->get_core_files();
		foreach ( $core_files as $file ) {
			$relative_path = str_replace( ABSPATH, '', $file );
			$backup_path   = $backup_dir . '/' . $relative_path;
			wp_mkdir_p( dirname( $backup_path ) );
			copy( $file, $backup_path );
		}
	}

	private function backup_plugin( $plugin_file ) {
		$backup_dir = WP_CONTENT_DIR . '/security-backups/plugins/' . dirname( $plugin_file ) . '/' . date( 'Y-m-d-H-i-s' );
		wp_mkdir_p( $backup_dir );

		$plugin_dir = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );
		$this->recursive_copy( $plugin_dir, $backup_dir );
	}

	private function recursive_copy( $src, $dst ) {
		$dir = opendir( $src );
		wp_mkdir_p( $dst );

		while ( ( $file = readdir( $dir ) ) !== false ) {
			if ( $file != '.' && $file != '..' ) {
				if ( is_dir( $src . '/' . $file ) ) {
					$this->recursive_copy( $src . '/' . $file, $dst . '/' . $file );
				} else {
					copy( $src . '/' . $file, $dst . '/' . $file );
				}
			}
		}

		closedir( $dir );
	}

	private function get_core_files() {
		$core_files = array();
		$iterator   = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( ABSPATH )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$path = $file->getPathname();
				if ( strpos( $path, WP_CONTENT_DIR ) === false ) {
					$core_files[] = $path;
				}
			}
		}

		return $core_files;
	}

	private function verify_core_files() {
		global $wp_version;

		$api_url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $wp_version,
				'locale'  => get_locale(),
			)
		);

		$response = wp_remote_get( $api_url );
		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( empty( $data['checksums'] ) ) {
			return false;
		}

		$modified_files = array();
		foreach ( $data['checksums'] as $file => $checksum ) {
			$path = ABSPATH . $file;
			if ( file_exists( $path ) && md5_file( $path ) !== $checksum ) {
				$modified_files[] = $file;
			}
		}

		if ( ! empty( $modified_files ) ) {
			$this->core_repair->repair_core_files( $modified_files );
		}

		return true;
	}

	private function is_core_healthy() {
		global $wp_version;

		// Check WordPress version
		$core = get_site_transient( 'update_core' );
		if ( ! empty( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( $update->response === 'upgrade' && version_compare( $wp_version, $update->current, '<' ) ) {
					return false;
				}
			}
		}

		// Verify core files
		return $this->verify_core_files();
	}

	public function force_updates() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized' );
		}

		delete_option( $this->last_check_option );
		$this->check_all_updates();

		wp_redirect( admin_url( 'admin.php?page=wp-security-hardening&updated=true' ) );
		exit;
	}
}
