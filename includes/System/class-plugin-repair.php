<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Plugin_Repair {
	private $quarantine;
	private $logger;
	private $last_check_option = 'wp_security_plugin_last_check';

	public function __construct() {
		require_once __DIR__ . '/class-quarantine-manager.php';
		require_once __DIR__ . '/class-logger.php';

		$this->quarantine = new WP_Security_Quarantine_Manager();
		$this->logger     = new WP_Security_Logger();

		// Check plugins every 6 hours
		add_action( 'wp_security_plugin_check', array( $this, 'check_plugins' ) );
		if ( ! wp_next_scheduled( 'wp_security_plugin_check' ) ) {
			wp_schedule_event( time(), 'sixhours', 'wp_security_plugin_check' );
		}
	}

	public function check_plugins() {
		// Skip if checked recently
		$last_check = get_option( $this->last_check_option, 0 );
		if ( ( time() - $last_check ) < HOUR_IN_SECONDS ) {
			return;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$this->check_plugin( $plugin_file, $plugin_data );
		}

		update_option( $this->last_check_option, time() );
	}

	public function check_plugin( $plugin_file, $plugin_data ) {
		$plugin_path = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );

		// Skip if plugin doesn't exist
		if ( ! is_dir( $plugin_path ) ) {
			return;
		}

		// Get plugin info from WordPress.org
		$plugin_info = $this->get_plugin_info( dirname( $plugin_file ) );
		if ( ! $plugin_info ) {
			return;
		}

		// Check for updates
		if ( version_compare( $plugin_data['Version'], $plugin_info['version'], '<' ) ) {
			$this->update_plugin( $plugin_file, $plugin_info );
		}

		// Check file integrity
		$this->verify_plugin_files( $plugin_file, $plugin_data );
	}

	private function get_plugin_info( $slug ) {
		if ( empty( $slug ) ) {
			return false;
		}

		$url      = "https://api.wordpress.org/plugins/info/1.0/{$slug}.json";
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return json_decode( wp_remote_retrieve_body( $response ), true );
	}

	private function update_plugin( $plugin_file, $plugin_info ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';

		// Backup current version
		$this->backup_plugin( $plugin_file );

		// Update plugin
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $plugin_file );

		if ( ! is_wp_error( $result ) ) {
			$this->logger->log( 'plugin_update', "Updated plugin: {$plugin_file}" );
			return true;
		}

		$this->logger->log( 'plugin_update', "Failed to update plugin: {$plugin_file}", 'error' );
		return false;
	}

	public function restore_plugin_backup( $plugin_file ) {
		$backup_dir = WP_CONTENT_DIR . '/security-backups/plugins/' . dirname( $plugin_file );

		// Get latest backup
		$backups = glob( $backup_dir . '/*', GLOB_ONLYDIR );
		if ( empty( $backups ) ) {
			$this->logger->log( 'plugin_repair', "No backup found for plugin: {$plugin_file}", 'error' );
			return false;
		}

		// Sort by date (newest first)
		usort(
			$backups,
			function ( $a, $b ) {
				return filemtime( $b ) - filemtime( $a );
			}
		);

		$latest_backup = $backups[0];
		$plugin_dir    = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );

		// Remove current version
		if ( is_dir( $plugin_dir ) ) {
			$this->recursive_rmdir( $plugin_dir );
		}

		// Restore from backup
		if ( $this->recursive_copy( $latest_backup, $plugin_dir ) ) {
			$this->logger->log( 'plugin_repair', "Restored plugin from backup: {$plugin_file}" );
			return true;
		}

		$this->logger->log( 'plugin_repair', "Failed to restore plugin from backup: {$plugin_file}", 'error' );
		return false;
	}

	private function verify_plugin_files( $plugin_file, $plugin_data ) {
		$plugin_path  = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );
		$plugin_files = $this->get_plugin_files( $plugin_path );

		foreach ( $plugin_files as $file ) {
			if ( $this->is_suspicious_file( $file ) ) {
				$this->quarantine->quarantine_file( $file );
				unlink( $file );
				$this->logger->log( 'plugin_security', "Removed suspicious file: {$file}" );
				continue;
			}

			if ( $this->contains_malicious_code( $file ) ) {
				$this->quarantine->quarantine_file( $file );
				$this->restore_plugin_file( $plugin_file, $file );
				$this->logger->log( 'plugin_security', "Restored compromised file: {$file}" );
			}
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

	private function get_plugin_files( $plugin_dir ) {
		$files    = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $plugin_dir )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	private function is_suspicious_file( $file ) {
		$suspicious_patterns = array(
			'/^[a-f0-9]{8,}\.php$/i',  // Random named PHP files
			'/\.(suspected|quarantine|infected)$/i',  // Known bad extensions
			'/^(?:info|cache|temp|tmp|bak)\.php$/i',  // Common malware names
		);

		$filename = basename( $file );
		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $filename ) ) {
				return true;
			}
		}

		return false;
	}

	private function contains_malicious_code( $file ) {
		// Skip non-PHP files
		if ( ! preg_match( '/\.php$/i', $file ) ) {
			return false;
		}

		$content = file_get_contents( $file );

		$malicious_patterns = array(
			'/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|strrev)\s*\([^\)]+\)\s*\)/i',
			'/\$[a-z0-9_]+\s*\(\s*\$[a-z0-9_]+\s*\)/i',  // Variable functions
			'/(?:exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(/i',
			'/preg_replace\s*\(\s*[\'"]\/[^\/]+\/e[\'"]\s*,/i',  // Eval via preg_replace
			'/\b(?:assert|create_function)\s*\(/i',
			'/\$(?:GLOBALS|_SERVER|_GET|_POST|_FILES|_COOKIE|_REQUEST|_ENV|HTTP_RAW_POST_DATA)\[/i',
		);

		foreach ( $malicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				return true;
			}
		}

		return false;
	}

	private function restore_plugin_file( $plugin_file, $compromised_file ) {
		$plugin_slug = dirname( $plugin_file );

		// Get plugin info
		$plugin_info = $this->get_plugin_info( $plugin_slug );
		if ( ! $plugin_info ) {
			return false;
		}

		// Download clean version
		$download_url = $plugin_info['download_link'];
		$temp_file    = download_url( $download_url );

		if ( is_wp_error( $temp_file ) ) {
			return false;
		}

		// Extract to temporary directory
		$temp_dir = WP_CONTENT_DIR . '/security-temp/' . uniqid( 'plugin_' );
		wp_mkdir_p( $temp_dir );

		$unzip_result = unzip_file( $temp_file, $temp_dir );
		unlink( $temp_file );

		if ( is_wp_error( $unzip_result ) ) {
			return false;
		}

		// Get relative path of compromised file
		$relative_path = str_replace( WP_PLUGIN_DIR . '/' . $plugin_slug . '/', '', $compromised_file );
		$clean_file    = $temp_dir . '/' . $plugin_slug . '/' . $relative_path;

		// Restore file if it exists in clean version
		if ( file_exists( $clean_file ) ) {
			copy( $clean_file, $compromised_file );
			chmod( $compromised_file, 0644 );
		}

		// Cleanup
		$this->recursive_rmdir( $temp_dir );
		return true;
	}

	private function recursive_rmdir( $dir ) {
		if ( is_dir( $dir ) ) {
			$objects = scandir( $dir );
			foreach ( $objects as $object ) {
				if ( $object != '.' && $object != '..' ) {
					if ( is_dir( $dir . '/' . $object ) ) {
						$this->recursive_rmdir( $dir . '/' . $object );
					} else {
						unlink( $dir . '/' . $object );
					}
				}
			}
			rmdir( $dir );
		}
	}
}
