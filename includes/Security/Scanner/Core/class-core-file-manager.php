<?php

namespace WP_Security\Scanner\Core;

class CoreFileManager {
	private const WP_API_CHECKSUMS = 'https://api.wordpress.org/core/checksums/1.0/';
	private const CORE_PATHS       = array(
		'wp-admin',
		'wp-includes',
		'index.php',
		'wp-config-sample.php',
		'wp-settings.php',
	);

	private $logger;

	public function __construct( $logger ) {
		$this->logger = $logger;
	}

	public function verify_and_restore( string $file_path ): bool {
		$relative_path = str_replace( ABSPATH, '', $file_path );
		if ( ! $this->is_core_file( $relative_path ) ) {
			return false;
		}

		$checksums = $this->get_core_checksums();
		if ( ! isset( $checksums[ $relative_path ] ) ) {
			return false;
		}

		if ( md5_file( $file_path ) !== $checksums[ $relative_path ] ) {
			return $this->restore_core_file( $relative_path );
		}

		return false;
	}

	private function is_core_file( string $relative_path ): bool {
		foreach ( self::CORE_PATHS as $core_path ) {
			if ( strpos( $relative_path, $core_path ) === 0 ) {
				return true;
			}
		}
		return false;
	}

	private function restore_core_file( string $relative_path ): bool {
		try {
			$wp_version   = $this->get_wordpress_version();
			$download_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$wp_version}/{$relative_path}";

			$content = file_get_contents( $download_url );
			if ( $content === false ) {
				throw new \Exception( 'Failed to download core file' );
			}

			$full_path = ABSPATH . '/' . $relative_path;
			if ( file_put_contents( $full_path, $content ) ) {
				$this->logger->info(
					'Core file restored',
					array(
						'file'    => $relative_path,
						'version' => $wp_version,
					)
				);
				return true;
			}
		} catch ( \Exception $e ) {
			$this->logger->error(
				'Failed to restore core file',
				array(
					'file'  => $relative_path,
					'error' => $e->getMessage(),
				)
			);
		}
		return false;
	}

	private function get_core_checksums(): array {
		try {
			$wp_version = $this->get_wordpress_version();
			$url        = self::WP_API_CHECKSUMS . "?version={$wp_version}&locale=" . get_locale();

			$response = wp_remote_get( $url );
			if ( is_wp_error( $response ) ) {
				throw new \Exception( $response->get_error_message() );
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			return $data['checksums'] ?? array();
		} catch ( \Exception $e ) {
			$this->logger->error(
				'Failed to get core checksums',
				array(
					'error' => $e->getMessage(),
				)
			);
			return array();
		}
	}

	private function get_wordpress_version(): string {
		return defined( 'WP_VERSION' ) ? WP_VERSION : get_bloginfo( 'version' );
	}
}
