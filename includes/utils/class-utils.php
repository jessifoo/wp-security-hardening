<?php

namespace WP_Security\Utils;

/**
 * Utility functions for the WordPress Security Hardening plugin.
 *
 * @package WP_Security
 * @subpackage Utils
 * @since 1.0.0
 */
class WP_Security_Utils {
	/**
	 * Makes an HTTP request to the WordPress.org API.
	 *
	 * @since 1.0.0
	 * @param string $url The API endpoint URL.
	 * @param array  $args Optional. Request arguments.
	 * @return array|\WP_Error Response array or WP_Error on failure.
	 */
	public function wp_api_request( string $url, array $args = array() ): array|\WP_Error {
		$response = wp_remote_get( $url, $args );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return new \WP_Error( 'json_decode_error', 'Failed to decode API response' );
		}

		return $data;
	}

	/**
	 * Gets the MD5 hash of a file.
	 *
	 * @since 1.0.0
	 * @param string $file Path to the file.
	 * @return string|false MD5 hash of the file or false on failure.
	 */
	public function get_file_hash( string $file ): string|false {
		if ( ! file_exists( $file ) ) {
			return false;
		}
		return md5_file( $file );
	}

	/**
	 * Gets a list of WordPress core files in a directory.
	 *
	 * @since 1.0.0
	 * @param string $directory Directory to scan.
	 * @return array List of core files.
	 */
	public function get_core_files( string $directory ): array {
		$files    = array();
		$dir      = new \RecursiveDirectoryIterator( $directory );
		$iterator = new \RecursiveIteratorIterator( $dir );

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && $this->is_core_file( $file->getPathname() ) ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Checks if a file is part of WordPress core.
	 *
	 * @since 1.0.0
	 * @param string $file Path to the file.
	 * @return bool True if the file is part of core, false otherwise.
	 */
	public function is_core_file( string $file ): bool {
		$core_directories = array( 'wp-admin', 'wp-includes' );
		$file_dir         = dirname( $file );

		foreach ( $core_directories as $dir ) {
			if ( strpos( $file_dir, $dir ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Creates a backup of a file.
	 *
	 * @since 1.0.0
	 * @param string $file Path to the file.
	 * @return bool True on success, false on failure.
	 */
	public function backup_file( string $file ): bool {
		if ( ! file_exists( $file ) ) {
			return false;
		}

		$backup_file = $file . '.bak.' . time();
		return copy( $file, $backup_file );
	}

	/**
	 * Downloads a file from a URL.
	 *
	 * @since 1.0.0
	 * @param string $url URL to download from.
	 * @param string $destination Where to save the file.
	 * @return bool True on success, false on failure.
	 */
	public function download_file( string $url, string $destination ): bool {
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		return file_put_contents( $destination, $body ) !== false;
	}

	/**
	 * Gets the WordPress locale.
	 *
	 * @since 1.0.0
	 * @return string WordPress locale.
	 */
	public function get_wp_locale(): string {
		return get_locale();
	}

	/**
	 * Gets the WordPress version.
	 *
	 * @since 1.0.0
	 * @return string WordPress version.
	 */
	public function get_wp_version(): string {
		global $wp_version;
		return $wp_version;
	}

	/**
	 * Checks if a file has secure permissions.
	 *
	 * @since 1.0.0
	 * @param string $file Path to the file.
	 * @return bool True if permissions are secure, false otherwise.
	 */
	public function has_secure_permissions( string $file ): bool {
		if ( ! file_exists( $file ) ) {
			return false;
		}

		$perms = fileperms( $file );

		if ( is_dir( $file ) ) {
			// Directory should be 755 or more restrictive
			return ( $perms & 0777 ) <= 0755;
		} else {
			// File should be 644 or more restrictive
			return ( $perms & 0777 ) <= 0644;
		}
	}

	/**
	 * Sanitizes a file path.
	 *
	 * @since 1.0.0
	 * @param string $path Path to sanitize.
	 * @return string Sanitized path.
	 */
	public function sanitize_path( string $path ): string {
		$path = str_replace( '\\', '/', $path );
		$path = preg_replace( '|/+|', '/', $path );
		return rtrim( $path, '/' );
	}

	/**
	 * Checks if the server is running on Windows.
	 *
	 * @since 1.0.0
	 * @return bool True if Windows, false otherwise.
	 */
	public function is_windows(): bool {
		return strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN';
	}

	/**
	 * Gets the system's temporary directory.
	 *
	 * @since 1.0.0
	 * @return string Path to temp directory.
	 */
	public function get_temp_dir(): string {
		if ( function_exists( 'sys_get_temp_dir' ) ) {
			return sys_get_temp_dir();
		}

		if ( ! empty( $_SERVER['TMP'] ) ) {
			return $_SERVER['TMP'];
		}

		return '/tmp';
	}

	/**
	 * Creates a temporary filename.
	 *
	 * @since 1.0.0
	 * @param string $prefix Optional. File prefix.
	 * @return string Temporary filename.
	 */
	public function create_temp_filename( string $prefix = '' ): string {
		$temp_dir = $this->get_temp_dir();
		return tempnam( $temp_dir, $prefix );
	}

	/**
	 * Gets WordPress core paths.
	 *
	 * @since 1.0.0
	 * @return array Array of core paths.
	 */
	public static function get_wp_paths(): array {
		return array(
			'root'     => ABSPATH,
			'admin'    => ABSPATH . 'wp-admin/',
			'includes' => ABSPATH . 'wp-includes/',
			'content'  => WP_CONTENT_DIR . '/',
			'plugins'  => WP_PLUGIN_DIR . '/',
			'themes'   => get_theme_root() . '/',
			'uploads'  => wp_upload_dir()['basedir'] . '/',
		);
	}

	/**
	 * Gets WordPress core file checksums from the WordPress API.
	 *
	 * @since 1.0.0
	 * @return array|false Array of checksums or false on failure.
	 */
	public static function get_core_checksums(): array|false {
		global $wp_version;
		$locale = get_locale();

		$url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $wp_version,
				'locale'  => $locale,
			)
		);

		$response = wp_remote_get( $url );
		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! $data || ! isset( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
			return false;
		}

		return $data['checksums'];
	}

	/**
	 * Reads a file's contents.
	 *
	 * @since 1.0.0
	 * @param string $file Path to file.
	 * @return string|false File contents or false on failure.
	 */
	public static function read_file( string $file ): string|false {
		if ( ! file_exists( $file ) || ! is_readable( $file ) ) {
			return false;
		}
		return file_get_contents( $file );
	}

	/**
	 * Writes content to a file.
	 *
	 * @since 1.0.0
	 * @param string $file Path to file.
	 * @param string $content Content to write.
	 * @return bool True on success, false on failure.
	 */
	public static function write_file( string $file, string $content ): bool {
		$dir = dirname( $file );
		if ( ! file_exists( $dir ) ) {
			if ( ! wp_mkdir_p( $dir ) ) {
				return false;
			}
		}

		if ( file_exists( $file ) && ! is_writable( $file ) ) {
			return false;
		}

		return file_put_contents( $file, $content ) !== false;
	}

	/**
	 * Gets all files in a directory recursively.
	 *
	 * @since 1.0.0
	 * @param string $dir Directory path.
	 * @return array Array of file paths.
	 */
	public static function get_files_recursive( string $dir ): array {
		$files = array();

		if ( ! is_dir( $dir ) ) {
			return $files;
		}

		$dir_iterator = new \RecursiveDirectoryIterator( $dir );
		$iterator     = new \RecursiveIteratorIterator( $dir_iterator, \RecursiveIteratorIterator::SELF_FIRST );

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}
}
