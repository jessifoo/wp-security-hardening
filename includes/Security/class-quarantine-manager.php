<?php
namespace WP_Security\Security;

class QuarantineManager {
	private $wpdb;
	private $quarantine_dir;
	private $encryption_key;

	public function __construct() {
		global $wpdb;
		$this->wpdb           = $wpdb;
		$this->quarantine_dir = WP_CONTENT_DIR . '/security-quarantine';
		$this->encryption_key = wp_salt( 'auth' );

		// Ensure quarantine directory exists
		wp_mkdir_p( $this->quarantine_dir );
		file_put_contents( $this->quarantine_dir . '/.htaccess', 'deny from all' );
	}

	public function quarantineFile( string $file_path, string $threat_type ): bool {
		try {
			// Generate quarantine path
			$quarantine_path = $this->quarantine_dir . '/' . uniqid( 'quarantine_' ) . '_' . basename( $file_path );

			// Create a lock file
			$lock_file = $quarantine_path . '.lock';
			$fp        = fopen( $lock_file, 'w' );

			if ( ! flock( $fp, LOCK_EX ) ) {
				throw new \Exception( 'Could not acquire lock' );
			}

			// Copy and encrypt file
			$content   = file_get_contents( $file_path );
			$encrypted = $this->encryptContent( $content );
			file_put_contents( $quarantine_path, $encrypted );

			// Store metadata
			$this->storeQuarantineMetadata( $file_path, $quarantine_path, $threat_type );

			// Remove original file
			unlink( $file_path );

			flock( $fp, LOCK_UN );
			fclose( $fp );
			unlink( $lock_file );

			return true;

		} catch ( \Exception $e ) {
			error_log( 'Quarantine failed: ' . $e->getMessage() );
			return false;
		}
	}

	private function encryptContent( string $content ): string {
		$iv        = openssl_random_pseudo_bytes( openssl_cipher_iv_length( 'AES-256-CBC' ) );
		$encrypted = openssl_encrypt(
			$content,
			'AES-256-CBC',
			$this->encryption_key,
			0,
			$iv
		);
		return base64_encode( $iv . $encrypted );
	}

	private function storeQuarantineMetadata( string $original_path, string $quarantine_path, string $threat_type ): void {
		$this->wpdb->insert(
			$this->wpdb->prefix . 'security_quarantine',
			array(
				'file_path'      => $quarantine_path,
				'original_path'  => $original_path,
				'file_hash'      => hash_file( 'sha256', $quarantine_path ),
				'threat_type'    => $threat_type,
				'encrypted'      => 1,
				'metadata'       => json_encode(
					array(
						'size'                 => filesize( $quarantine_path ),
						'quarantined_by'       => get_current_user_id(),
						'original_permissions' => fileperms( $original_path ),
					)
				),
				'quarantined_at' => current_time( 'mysql' ),
			)
		);
	}
}
