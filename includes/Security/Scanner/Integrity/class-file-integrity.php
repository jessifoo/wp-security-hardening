<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_File_Integrity {
	private $suspicious_patterns = array(
		'empty_php'        => array(
			'pattern' => '/\.php$/i',
			'size'    => 0,
		),
		'encoded_content'  => array(
			'pattern'  => '/(?:eval|base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/i',
			'max_size' => 1048576,  // 1MB
		),
		'suspicious_names' => array(
			'pattern' => '/[0-9a-f]{8,}\.php$/i',
		),
		'hidden_files'     => array(
			'pattern' => '/^\./i',
		),
		'non_wp_uploads'   => array(
			'pattern' => '/\.(php|phtml|php3|php4|php5|php7|pht|phar|exe|sh|asp|aspx|jsp|cgi)$/i',
			'dirs'    => array( 'wp-content/uploads' ),
		),
	);

	private $last_scan_option  = 'wp_security_last_integrity_scan';
	private $baseline_option   = 'wp_security_file_baseline';
	private $changes_option    = 'wp_security_file_changes';
	private $hashes_option     = 'wp_security_file_hashes';
	private $last_check_option = 'wp_security_last_file_check';
	private $check_interval    = 3600; // 1 hour
	private $notification_email;
	private $logger;
	private $api_utils;
	private $file_utils;
	private $code_utils;

	private $critical_files = array(
		'wp-config.php',
		'.htaccess',
		'index.php',
		'wp-settings.php',
		'wp-load.php',
		'wp-blog-header.php',
		'wp-cron.php',
		'wp-login.php',
		'xmlrpc.php',
	);

	private $critical_directories = array(
		'wp-admin',
		'wp-includes',
		'wp-content/plugins',
		'wp-content/themes',
	);

	public function __construct() {
		require_once __DIR__ . '/class-logger.php';
		$this->logger             = new WP_Security_Logger();
		$this->api_utils          = new WP_Security_API_Utils();
		$this->file_utils         = new WP_Security_File_Utils();
		$this->code_utils         = new WP_Security_Code_Utils();
		$this->notification_email = get_option( 'admin_email' );

		// Schedule scans
		add_action( 'wp_security_hourly_scan', array( $this, 'scan' ) );
		add_action( 'wp_security_create_baseline', array( $this, 'create_baseline' ) );
		add_action( 'wp_security_file_check', array( $this, 'check_critical_files' ) );

		if ( ! wp_next_scheduled( 'wp_security_file_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'wp_security_file_check' );
		}
	}

	public function check_critical_files() {
		$last_check = get_option( $this->last_check_option, 0 );

		if ( ( time() - $last_check ) < $this->check_interval ) {
			return;
		}

		$changes        = array();
		$current_hashes = array();
		$suspicious     = array();

		// Check critical files
		foreach ( $this->critical_files as $file ) {
			$path = ABSPATH . $file;
			if ( file_exists( $path ) ) {
				$current_hash            = md5_file( $path );
				$current_hashes[ $file ] = $current_hash;

				$this->check_file_changes( $file, $path, $current_hash, $changes );
				$this->check_file_integrity( $path, $suspicious );
			}
		}

		// Check critical directories
		foreach ( $this->critical_directories as $dir ) {
			$path = ABSPATH . $dir;
			if ( is_dir( $path ) ) {
				$this->scan_critical_directory( $path, $dir, $current_hashes, $changes, $suspicious );
			}
		}

		// Save current hashes and update last check time
		update_option( $this->hashes_option, $current_hashes );
		update_option( $this->last_check_option, time() );

		// Handle any changes or suspicious files
		if ( ! empty( $changes ) ) {
			$this->handle_changes( $changes );
		}
		if ( ! empty( $suspicious ) ) {
			$this->alert_suspicious_files( $suspicious );
			$this->quarantine_files( $suspicious );
		}
	}

	private function scan_critical_directory( $path, $relative_path, &$current_hashes, &$changes, &$suspicious ) {
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $path, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $files as $file ) {
			if ( $file->isFile() ) {
				$file_path     = $file->getPathname();
				$relative_file = str_replace( ABSPATH, '', $file_path );

				// Skip large files and non-PHP files for performance
				if ( $file->getSize() > 5 * 1024 * 1024 || pathinfo( $file_path, PATHINFO_EXTENSION ) !== 'php' ) {
					continue;
				}

				$current_hash                     = md5_file( $file_path );
				$current_hashes[ $relative_file ] = $current_hash;

				$this->check_file_changes( $relative_file, $file_path, $current_hash, $changes );
				$this->check_file_integrity( $file_path, $suspicious );
			}
		}
	}

	private function check_file_changes( $relative_file, $file_path, $current_hash, &$changes ) {
		$stored_hashes = get_option( $this->hashes_option, array() );

		if ( isset( $stored_hashes[ $relative_file ] ) && $stored_hashes[ $relative_file ] !== $current_hash ) {
			$changes[] = array(
				'file'        => $relative_file,
				'type'        => 'modified',
				'time'        => time(),
				'size'        => filesize( $file_path ),
				'permissions' => substr( sprintf( '%o', fileperms( $file_path ) ), -4 ),
			);

			do_action( 'wp_security_file_changed', $file_path, 'modified' );
			$this->logger->log(
				'file_monitoring',
				"File modified: {$relative_file}",
				'warning',
				array(
					'file' => $relative_file,
					'hash' => $current_hash,
				)
			);
		} elseif ( ! isset( $stored_hashes[ $relative_file ] ) ) {
			$changes[] = array(
				'file'        => $relative_file,
				'type'        => 'added',
				'time'        => time(),
				'size'        => filesize( $file_path ),
				'permissions' => substr( sprintf( '%o', fileperms( $file_path ) ), -4 ),
			);

			do_action( 'wp_security_file_changed', $file_path, 'added' );
			$this->logger->log(
				'file_monitoring',
				"New file detected: {$relative_file}",
				'warning',
				array(
					'file' => $relative_file,
					'hash' => $current_hash,
				)
			);
		}
	}

	private function handle_changes( $changes ) {
		if ( empty( $changes ) ) {
			return;
		}

		// Store changes
		$stored_changes = get_option( $this->changes_option, array() );
		$stored_changes = array_merge( $stored_changes, $changes );

		// Keep only last 1000 changes
		if ( count( $stored_changes ) > 1000 ) {
			$stored_changes = array_slice( $stored_changes, -1000 );
		}

		update_option( $this->changes_option, $stored_changes );

		// Notify admin
		$this->notify_changes( $changes );
	}

	private function notify_changes( $changes ) {
		if ( empty( $changes ) || ! is_email( $this->notification_email ) ) {
			return;
		}

		$message = "The following file changes were detected on your WordPress site:\n\n";

		foreach ( $changes as $change ) {
			$message .= sprintf(
				"%s: %s\nTime: %s\nSize: %d bytes\nPermissions: %s\n\n",
				ucfirst( $change['type'] ),
				$change['file'],
				date( 'Y-m-d H:i:s', $change['time'] ),
				$change['size'],
				$change['permissions']
			);
		}

		wp_mail(
			$this->notification_email,
			'WordPress Security - File Changes Detected',
			$message,
			array( 'Content-Type: text/plain; charset=UTF-8' )
		);
	}

	public function scan() {
		$start_time = time();
		$changes    = array();
		$suspicious = array();
		$baseline   = get_option( $this->baseline_option, array() );

		// Scan WordPress directories
		$dirs_to_scan = array(
			ABSPATH                 => 'WordPress Root',
			ABSPATH . 'wp-admin'    => 'WordPress Admin',
			ABSPATH . 'wp-includes' => 'WordPress Core',
			WP_CONTENT_DIR          => 'wp-content',
			WP_PLUGIN_DIR           => 'Plugins',
			get_theme_root()        => 'Themes',
		);

		foreach ( $dirs_to_scan as $dir => $label ) {
			$this->scan_directory( $dir, $baseline, $changes, $suspicious );
		}

		// Store results
		update_option( $this->changes_option, $changes );
		update_option( $this->last_scan_option, $start_time );

		// Alert if suspicious files found
		if ( ! empty( $suspicious ) ) {
			$this->alert_suspicious_files( $suspicious );
			$this->quarantine_files( $suspicious );
		}

		return array(
			'changes'    => $changes,
			'suspicious' => $suspicious,
			'duration'   => time() - $start_time,
		);
	}

	private function scan_directory( $dir, $baseline, &$changes, &$suspicious ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$path          = wp_normalize_path( $file->getPathname() );
				$relative_path = str_replace( ABSPATH, '', $path );

				// Check for suspicious patterns
				foreach ( $this->suspicious_patterns as $type => $check ) {
					if ( preg_match( $check['pattern'], $path ) ) {
						// For empty PHP files
						if ( isset( $check['size'] ) && $file->getSize() === $check['size'] ) {
							$suspicious[] = array(
								'path'  => $path,
								'type'  => $type,
								'size'  => $file->getSize(),
								'mtime' => $file->getMTime(),
							);
							continue;
						}

						// For encoded content
						if ( isset( $check['max_size'] ) && $file->getSize() <= $check['max_size'] ) {
							$content = file_get_contents( $path );
							if ( preg_match( $check['pattern'], $content ) ) {
								$suspicious[] = array(
									'path'  => $path,
									'type'  => $type,
									'size'  => $file->getSize(),
									'mtime' => $file->getMTime(),
								);
								continue;
							}
						}

						// For files in uploads
						if ( isset( $check['dirs'] ) ) {
							foreach ( $check['dirs'] as $restricted_dir ) {
								if ( strpos( $path, $restricted_dir ) !== false ) {
									$suspicious[] = array(
										'path'  => $path,
										'type'  => $type,
										'size'  => $file->getSize(),
										'mtime' => $file->getMTime(),
									);
									continue 2;
								}
							}
						}
					}
				}

				// Check for changes against baseline
				if ( isset( $baseline[ $relative_path ] ) ) {
					$current_hash = md5_file( $path );
					if ( $current_hash !== $baseline[ $relative_path ]['hash'] ) {
						$changes[] = array(
							'path'     => $path,
							'type'     => 'modified',
							'old_hash' => $baseline[ $relative_path ]['hash'],
							'new_hash' => $current_hash,
							'mtime'    => $file->getMTime(),
						);
					}
				} else {
					$changes[] = array(
						'path'  => $path,
						'type'  => 'added',
						'hash'  => md5_file( $path ),
						'mtime' => $file->getMTime(),
					);
				}
			}
		}
	}

	public function create_baseline() {
		$baseline     = array();
		$dirs_to_scan = array(
			ABSPATH,
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
			WP_CONTENT_DIR,
			WP_PLUGIN_DIR,
			get_theme_root(),
		);

		foreach ( $dirs_to_scan as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$path                       = wp_normalize_path( $file->getPathname() );
					$relative_path              = str_replace( ABSPATH, '', $path );
					$baseline[ $relative_path ] = array(
						'hash'  => md5_file( $path ),
						'size'  => $file->getSize(),
						'mtime' => $file->getMTime(),
					);
				}
			}
		}

		update_option( $this->baseline_option, $baseline );
		return $baseline;
	}

	private function alert_suspicious_files( $suspicious ) {
		$admin_email = get_option( 'admin_email' );
		$site_url    = get_site_url();

		$message = "Suspicious files detected on {$site_url}:\n\n";

		foreach ( $suspicious as $file ) {
			$message .= sprintf(
				"File: %s\nType: %s\nSize: %d bytes\nModified: %s\n\n",
				$file['path'],
				$file['type'],
				$file['size'],
				date( 'Y-m-d H:i:s', $file['mtime'] )
			);
		}

		$message .= "\nThese files have been automatically quarantined for review.\n";
		$message .= "Please check your security dashboard for more details.\n";

		wp_mail(
			$admin_email,
			'[WordPress Security] Suspicious Files Detected',
			$message
		);
	}

	private function quarantine_files( $suspicious ) {
		$quarantine_dir = WP_CONTENT_DIR . '/security-quarantine';
		if ( ! file_exists( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
			WP_Security_File_Utils::write_file( $quarantine_dir . '/.htaccess', 'Deny from all' );
			WP_Security_File_Utils::write_file( $quarantine_dir . '/index.php', '<?php // Silence is golden.' );
		}

		foreach ( $suspicious as $file ) {
			$original_path   = $file['path'];
			$quarantine_path = $quarantine_dir . '/' . md5( $original_path ) . '_' . basename( $original_path );

			// Move file to quarantine
			if ( @rename( $original_path, $quarantine_path ) ) {
				// Log the quarantine action
				$this->log_quarantine_action( $original_path, $quarantine_path, $file );
			}
		}
	}

	private function log_quarantine_action( $original_path, $quarantine_path, $file_data ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'security_quarantine_log';

		$wpdb->insert(
			$table_name,
			array(
				'original_path'   => $original_path,
				'quarantine_path' => $quarantine_path,
				'file_type'       => $file_data['type'],
				'file_size'       => $file_data['size'],
				'detection_time'  => current_time( 'mysql' ),
				'file_hash'       => md5_file( $quarantine_path ),
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	public function run_integrity_check() {
		return WP_Security_Performance_Profiler::profile_callback(
			'run_integrity_check',
			function () {
				$changes        = array();
				$critical_files = $this->get_critical_files();

				foreach ( $critical_files as $file ) {
					$result = $this->check_file_integrity( $file );

					if ( $result['status'] === 'suspicious' ) {
						$changes[] = array(
							'file'                => $file,
							'type'                => 'critical_file_modified',
							'dangerous_functions' => $result['dangerous_functions'],
							'obfuscation'         => $result['obfuscation_detected'],
							'backup_path'         => $result['backup_path'],
							'timestamp'           => gmdate( 'Y-m-d H:i:s' ),
						);

						$this->logger->log(
							'file_integrity',
							sprintf( 'Critical file modified: %s', $file ),
							'warning',
							array(
								'file'    => $file,
								'changes' => $result,
							)
						);

						// Send notification if enabled
						if ( $this->should_notify() ) {
							$this->send_notification( $file, $result );
						}
					}
				}

				update_option(
					'wp_security_last_integrity_check',
					array(
						'timestamp' => time(),
						'changes'   => $changes,
					)
				);

				return $changes;
			},
			array()
		);
	}

	private function check_file_integrity( $file_path ) {
		return WP_Security_Performance_Profiler::profile_callback(
			'check_file_integrity',
			function ( $file_path ) {
				if ( ! WP_Security_File_Utils::is_scannable_file( $file_path ) ) {
					return array(
						'status' => 'skipped',
						'reason' => 'File type not supported for scanning',
					);
				}

				$content = WP_Security_File_Utils::read_file( $file_path );
				if ( false === $content ) {
					return array(
						'status' => 'error',
						'reason' => 'Unable to read file',
					);
				}

				// Check for malicious patterns
				$dangerous_funcs = $this->code_utils->find_dangerous_functions( $content );
				$obfuscation     = $this->code_utils->detect_obfuscation( $content );

				// If obfuscation detected, try to decode and recheck
				if ( ! empty( $obfuscation ) ) {
					$decoded_content = $this->code_utils->decode_content( $content );
					if ( $decoded_content !== $content ) {
						$dangerous_funcs = array_merge(
							$dangerous_funcs,
							$this->code_utils->find_dangerous_functions( $decoded_content )
						);
					}
				}

				// Create backup if issues found
				$backup_path = null;
				if ( ! empty( $dangerous_funcs ) || ! empty( $obfuscation ) ) {
					$backup_path = WP_Security_File_Utils::create_backup( $file_path );
				}

				return array(
					'status'               => empty( $dangerous_funcs ) && empty( $obfuscation ) ? 'clean' : 'suspicious',
					'dangerous_functions'  => $dangerous_funcs,
					'obfuscation_detected' => $obfuscation,
					'backup_path'          => $backup_path,
					'last_checked'         => gmdate( 'Y-m-d H:i:s' ),
				);
			},
			array( $file_path )
		);
	}

	private function get_critical_files() {
		$files = array();

		// Core files
		foreach ( $this->critical_files as $file ) {
			$path = ABSPATH . $file;
			if ( WP_Security_File_Utils::is_scannable_file( $path ) ) {
				$files[] = $path;
			}
		}

		// Active theme files
		$theme_root  = get_theme_root() . '/' . get_template();
		$theme_files = WP_Security_File_Utils::list_files( $theme_root, array( 'php', 'js' ) );
		$files       = array_merge( $files, $theme_files );

		// Active plugin files
		$active_plugins = get_option( 'active_plugins' );
		foreach ( $active_plugins as $plugin ) {
			$plugin_path  = WP_PLUGIN_DIR . '/' . dirname( $plugin );
			$plugin_files = WP_Security_File_Utils::list_files( $plugin_path, array( 'php', 'js' ) );
			$files        = array_merge( $files, $plugin_files );
		}

		return array_unique( $files );
	}

	private function send_notification( $file, $changes ) {
		$to      = $this->notification_email;
		$subject = sprintf( '[%s] Security Alert: Critical File Modified', get_bloginfo( 'name' ) );

		$message  = "A critical file has been modified on your WordPress site:\n\n";
		$message .= 'File: ' . $file . "\n";
		$message .= 'Time: ' . gmdate( 'Y-m-d H:i:s' ) . "\n\n";

		if ( ! empty( $changes['dangerous_functions'] ) ) {
			$message .= "Dangerous Functions Found:\n";
			foreach ( $changes['dangerous_functions'] as $func ) {
				$message .= '- ' . $func['function'] . ' (Context: ' . $func['context'] . ")\n";
			}
			$message .= "\n";
		}

		if ( ! empty( $changes['obfuscation_detected'] ) ) {
			$message .= "Obfuscation Detected:\n";
			foreach ( $changes['obfuscation_detected'] as $pattern ) {
				$message .= '- ' . $pattern['type'] . ' (Context: ' . $pattern['context'] . ")\n";
			}
		}

		if ( $changes['backup_path'] ) {
			$message .= "\nA backup has been created at: " . $changes['backup_path'] . "\n";
		}

		$message .= "\nPlease review these changes immediately.\n";
		$message .= 'Site URL: ' . get_site_url() . "\n";

		wp_mail( $to, $subject, $message );
	}

	private function should_notify() {
		$last_notification     = get_option( 'wp_security_last_notification', 0 );
		$notification_interval = 3600; // 1 hour

		if ( time() - $last_notification < $notification_interval ) {
			return false;
		}

		update_option( 'wp_security_last_notification', time() );
		return true;
	}

	public function get_last_scan_results() {
		return array(
			'last_scan'      => get_option( $this->last_scan_option ),
			'changes'        => get_option( $this->changes_option, array() ),
			'baseline_count' => count( get_option( $this->baseline_option, array() ) ),
		);
	}
}
