<?php

namespace WP_Security\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

/**
 * File monitoring class
 *
 * @package WP_Security
 */
class WP_Security_File_Monitor {
	/**
	 * @var string Option name for storing file hashes
	 */
	private const FILE_HASHES_OPTION = 'wp_security_file_hashes';

	/**
	 * Initialize the monitor
	 */
	public function __construct() {
		// Monitor file changes
		add_action( 'add_attachment', array( $this, 'monitor_upload' ) );
		add_action( 'delete_attachment', array( $this, 'monitor_deletion' ) );
		add_action( 'switch_theme', array( $this, 'monitor_theme_change' ) );
		add_action( 'activated_plugin', array( $this, 'monitor_plugin_activation' ) );
		add_action( 'deactivated_plugin', array( $this, 'monitor_plugin_deactivation' ) );

		// Monitor core/plugin/theme updates
		add_action( 'upgrader_process_complete', array( $this, 'monitor_updates' ), 10, 2 );

		// Schedule integrity checks
		if ( ! wp_next_scheduled( 'wp_security_file_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'wp_security_file_check' );
		}
		add_action( 'wp_security_file_check', array( $this, 'check_file_integrity' ) );
	}

	/**
	 * Monitor file upload
	 *
	 * @param int $attachment_id Attachment ID
	 */
	public function monitor_upload( $attachment_id ) {
		$file = get_attached_file( $attachment_id );
		if ( ! $file ) {
			return;
		}

		$hash = $this->get_file_hash( $file );
		$this->update_file_hash( $file, $hash );

		do_action( 'wp_security_file_uploaded', $file, $hash, $attachment_id );
	}

	/**
	 * Monitor file deletion
	 *
	 * @param int $attachment_id Attachment ID
	 */
	public function monitor_deletion( $attachment_id ) {
		$file = get_attached_file( $attachment_id );
		if ( ! $file ) {
			return;
		}

		$this->remove_file_hash( $file );
		do_action( 'wp_security_file_deleted', $file, $attachment_id );
	}

	/**
	 * Monitor theme changes
	 *
	 * @param WP_Theme $new_theme New theme object
	 */
	public function monitor_theme_change( $new_theme ) {
		$theme_dir = get_theme_root() . '/' . $new_theme->get_stylesheet();
		$this->scan_directory( $theme_dir );
		do_action( 'wp_security_theme_changed', $new_theme, $theme_dir );
	}

	/**
	 * Monitor updates
	 *
	 * @param WP_Upgrader $upgrader Upgrader instance
	 * @param array       $options  Update options
	 */
	public function monitor_updates( $upgrader, $options ) {
		if ( ! isset( $options['type'] ) ) {
			return;
		}

		$type   = $options['type'];
		$action = $options['action'] ?? '';

		if ( $action !== 'update' ) {
			return;
		}

		switch ( $type ) {
			case 'plugin':
				if ( ! empty( $options['plugins'] ) ) {
					foreach ( $options['plugins'] as $plugin ) {
						$this->scan_directory( WP_PLUGIN_DIR . '/' . dirname( $plugin ) );
					}
				}
				break;
			case 'theme':
				if ( ! empty( $options['themes'] ) ) {
					foreach ( $options['themes'] as $theme ) {
						$this->scan_directory( get_theme_root() . '/' . $theme );
					}
				}
				break;
			case 'core':
				$this->scan_directory( ABSPATH );
				break;
		}

		do_action( 'wp_security_updates_monitored', $type, $options );
	}

	/**
	 * Check file integrity
	 */
	public function check_file_integrity() {
		if ( ! apply_filters( 'wp_security_should_check_integrity', true ) ) {
			return;
		}

		$hashes  = get_option( self::FILE_HASHES_OPTION, array() );
		$changes = array();

		foreach ( $hashes as $file => $stored_hash ) {
			if ( ! file_exists( $file ) ) {
				$changes['deleted'][] = $file;
				continue;
			}

			$current_hash = $this->get_file_hash( $file );
			if ( $current_hash !== $stored_hash ) {
				$changes['modified'][] = $file;
			}
		}

		if ( ! empty( $changes ) ) {
			do_action( 'wp_security_integrity_changes', $changes );
		}

		do_action( 'wp_security_integrity_check_complete', $changes );
	}

	/**
	 * Get file hash
	 *
	 * @param string $file File path
	 * @return string|bool File hash or false on failure
	 */
	private function get_file_hash( $file ) {
		// Use WP Filesystem API
		require_once ABSPATH . 'wp-admin/includes/file.php';
		WP_Filesystem();
		global $wp_filesystem;

		if ( ! $wp_filesystem->exists( $file ) ) {
			return false;
		}

		return md5( $wp_filesystem->get_contents( $file ) );
	}

	/**
	 * Update file hash
	 *
	 * @param string $file File path
	 * @param string $hash File hash
	 */
	private function update_file_hash( $file, $hash ) {
		$hashes          = get_option( self::FILE_HASHES_OPTION, array() );
		$hashes[ $file ] = $hash;
		update_option( self::FILE_HASHES_OPTION, $hashes );
	}

	/**
	 * Remove file hash
	 *
	 * @param string $file File path
	 */
	private function remove_file_hash( $file ) {
		$hashes = get_option( self::FILE_HASHES_OPTION, array() );
		unset( $hashes[ $file ] );
		update_option( self::FILE_HASHES_OPTION, $hashes );
	}

	/**
	 * Scan directory for files
	 *
	 * @param string $dir Directory path
	 */
	private function scan_directory( $dir ) {
		$files = scandir( $dir );
		foreach ( $files as $file ) {
			if ( $file === '.' || $file === '..' ) {
				continue;
			}

			$file_path = $dir . '/' . $file;
			if ( is_file( $file_path ) ) {
				$hash = $this->get_file_hash( $file_path );
				$this->update_file_hash( $file_path, $hash );
			} elseif ( is_dir( $file_path ) ) {
				$this->scan_directory( $file_path );
			}
		}
	}
}
