<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Quarantine_Manager {
	private $quarantine_dir;
	private $quarantine_log;
	private $max_quarantine_size = 104857600; // 100MB
	private $max_quarantine_age  = 604800; // 7 days
	private $quarantine_option   = 'wp_security_quarantine_log';
	private $site_coordinator;

	public function __construct() {
		$upload_dir             = wp_upload_dir();
		$this->quarantine_dir   = $upload_dir['basedir'] . '/security-quarantine';
		$this->quarantine_log   = get_option( $this->quarantine_option, array() );
		$this->site_coordinator = WP_Security_Site_Coordinator::get_instance();

		// Create quarantine directory if it doesn't exist
		if ( ! file_exists( $this->quarantine_dir ) ) {
			wp_mkdir_p( $this->quarantine_dir );
			file_put_contents( $this->quarantine_dir . '/.htaccess', 'Deny from all' );
			file_put_contents( $this->quarantine_dir . '/index.php', '<?php // Silence is golden.' );
		}

		add_action( 'wp_security_cleanup_quarantine', array( $this, 'cleanup_quarantine' ) );
		if ( ! wp_next_scheduled( 'wp_security_cleanup_quarantine' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_cleanup_quarantine' );
		}
	}

	public function quarantine_file( $file_path, $threat_details ) {
		if ( ! file_exists( $file_path ) ) {
			return false;
		}

		// Check resource usage before quarantine operation
		if ( ! $this->site_coordinator->check_resource_usage() ) {
			error_log( 'Quarantine operation paused - Resource usage too high' );
			return false;
		}

		// Generate safe filename
		$quarantine_name = date( 'Y-m-d_H-i-s' ) . '_' . md5( $file_path ) . '.quar';
		$quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;

		// Create backup with metadata
		$metadata = array(
			'original_path'   => $file_path,
			'quarantine_time' => time(),
			'threat_details'  => $threat_details,
			'file_hash'       => md5_file( $file_path ),
			'file_size'       => filesize( $file_path ),
			'file_perms'      => fileperms( $file_path ),
		);

		// Encrypt and compress the file
		$success = $this->secure_file( $file_path, $quarantine_path, $metadata );
		if ( ! $success ) {
			return false;
		}

		// Log the quarantine
		$this->quarantine_log[] = array_merge(
			$metadata,
			array(
				'quarantine_path' => $quarantine_path,
				'quarantine_name' => $quarantine_name,
				'auto_clean'      => isset( $threat_details['auto_clean'] ) ? $threat_details['auto_clean'] : false,
			)
		);
		update_option( $this->quarantine_option, $this->quarantine_log );

		return true;
	}

	private function secure_file( $source_path, $dest_path, $metadata ) {
		return WP_Security_File_Utils::secure_file( $source_path, $dest_path, $metadata );
	}

	private function encrypt_data( $data ) {
		return WP_Security_File_Utils::encrypt_data( $data );
	}

	private function decrypt_data( $encrypted_data ) {
		return WP_Security_File_Utils::decrypt_data( $encrypted_data );
	}

	private function get_encryption_key() {
		return WP_Security_File_Utils::get_encryption_key();
	}

	public function restore_file( $quarantine_name ) {
		$quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;
		if ( ! file_exists( $quarantine_path ) ) {
			return false;
		}

		try {
			// Read and decrypt quarantined file
			$encrypted_data = file_get_contents( $quarantine_path );
			$decrypted_data = $this->decrypt_data( $encrypted_data );
			$package        = json_decode( $decrypted_data, true );

			if ( ! $package || ! isset( $package['metadata'] ) || ! isset( $package['content'] ) ) {
				return false;
			}

			$original_path = $package['metadata']['original_path'];
			$content       = base64_decode( $package['content'] );

			// Restore file
			if ( file_put_contents( $original_path, $content ) === false ) {
				return false;
			}

			// Restore permissions
			chmod( $original_path, $package['metadata']['file_perms'] );

			// Remove from quarantine
			unlink( $quarantine_path );

			// Update log
			$this->remove_from_log( $quarantine_name );

			return true;
		} catch ( Exception $e ) {
			error_log( 'Restore error: ' . $e->getMessage() );
			return false;
		}
	}

	public function delete_quarantined_file( $quarantine_name ) {
		$quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;
		if ( file_exists( $quarantine_path ) ) {
			unlink( $quarantine_path );
		}
		$this->remove_from_log( $quarantine_name );
		return true;
	}

	private function remove_from_log( $quarantine_name ) {
		foreach ( $this->quarantine_log as $key => $entry ) {
			if ( $entry['quarantine_name'] === $quarantine_name ) {
				unset( $this->quarantine_log[ $key ] );
				break;
			}
		}
		$this->quarantine_log = array_values( $this->quarantine_log );
		update_option( $this->quarantine_option, $this->quarantine_log );
	}

	public function get_quarantine_path( $file_path ) {
		return $this->quarantine_dir . '/' . date( 'Y-m-d_H-i-s' ) . '_' . md5( $file_path ) . '.quar';
	}

	public function cleanup_quarantine() {
		// Check resource usage before cleanup
		if ( ! $this->site_coordinator->check_resource_usage() ) {
			error_log( 'Quarantine cleanup paused - Resource usage too high' );
			return false;
		}

		$total_size   = 0;
		$current_time = time();

		foreach ( $this->quarantine_log as $key => $entry ) {
			$quarantine_path = $this->quarantine_dir . '/' . $entry['quarantine_name'];

			// Remove old files
			if ( ( $current_time - $entry['quarantine_time'] ) > $this->max_quarantine_age ) {
				$this->delete_quarantined_file( $entry['quarantine_name'] );
				continue;
			}

			// Calculate total size
			if ( file_exists( $quarantine_path ) ) {
				$total_size += filesize( $quarantine_path );
			}
		}

		// If total size exceeds limit, remove oldest files
		if ( $total_size > $this->max_quarantine_size ) {
			usort(
				$this->quarantine_log,
				function ( $a, $b ) {
					return $a['quarantine_time'] - $b['quarantine_time'];
				}
			);

			while ( $total_size > $this->max_quarantine_size && ! empty( $this->quarantine_log ) ) {
				$oldest          = array_shift( $this->quarantine_log );
				$quarantine_path = $this->quarantine_dir . '/' . $oldest['quarantine_name'];
				if ( file_exists( $quarantine_path ) ) {
					$total_size -= filesize( $quarantine_path );
					unlink( $quarantine_path );
				}
			}

			update_option( $this->quarantine_option, $this->quarantine_log );
		}
	}

	public function get_quarantine_list() {
		return $this->quarantine_log;
	}

	public function get_quarantine_stats() {
		$total_size       = 0;
		$file_count       = 0;
		$auto_clean_count = 0;

		foreach ( $this->quarantine_log as $entry ) {
			$quarantine_path = $this->quarantine_dir . '/' . $entry['quarantine_name'];
			if ( file_exists( $quarantine_path ) ) {
				$total_size += filesize( $quarantine_path );
				++$file_count;
				if ( ! empty( $entry['auto_clean'] ) ) {
					++$auto_clean_count;
				}
			}
		}

		return array(
			'total_size'       => $total_size,
			'file_count'       => $file_count,
			'auto_clean_count' => $auto_clean_count,
			'max_size'         => $this->max_quarantine_size,
			'max_age'          => $this->max_quarantine_age,
		);
	}
}
