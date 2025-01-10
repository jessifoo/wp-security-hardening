<?php
namespace WP_Security\Security\Scanner;

class InfectionScanner {
	private $logger;
	private $quarantine_manager;

	public function __construct( $logger, $quarantine_manager ) {
		$this->logger             = $logger;
		$this->quarantine_manager = $quarantine_manager;
	}

	public function scan_for_infections(): array {
		$results = array(
			'zero_byte_files'  => array(),
			'suspicious_files' => array(),
			'js_infections'    => array(),
			'db_infections'    => array(),
		);

		// 1. Scan for zero-byte and suspicious PHP files
		$this->scan_directories( $results );

		// 2. Check for JS infections
		$this->scan_js_files( $results );

		// 3. Check database
		$this->scan_database( $results );

		// 4. Clean infections
		$this->clean_infections( $results );

		return $results;
	}

	private function scan_directories( &$results ) {
		$directories = array(
			ABSPATH,
			WP_CONTENT_DIR,
			WP_PLUGIN_DIR,
			get_theme_root(),
		);

		foreach ( $directories as $dir ) {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $dir )
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					// Check for zero-byte files
					if ( $file->getSize() === 0 && pathinfo( $file->getFilename(), PATHINFO_EXTENSION ) === 'php' ) {
						$results['zero_byte_files'][] = $file->getPathname();
						$this->quarantine_manager->quarantineFile( $file->getPathname(), 'zero_byte' );
					}

					// Check for suspicious filenames
					if ( preg_match( '/^[a-z0-9]{8}\.php$/i', $file->getFilename() ) ) {
						$results['suspicious_files'][] = $file->getPathname();
						$this->quarantine_manager->quarantineFile( $file->getPathname(), 'suspicious_name' );
					}
				}
			}
		}
	}

	private function scan_js_files( &$results ) {
		$js_files = array(
			WP_CONTENT_DIR . '/themes/' . get_template() . '/js',
			WP_ADMIN . '/js',
			ABSPATH . WPINC . '/js',
		);

		foreach ( $js_files as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			foreach ( glob( $dir . '/*.js' ) as $file ) {
				$content = file_get_contents( $file );
				if ( preg_match( '/(eval|document\.write|unescape)\s*\(/', $content ) ) {
					$results['js_infections'][] = $file;
					// Create backup before cleaning
					copy( $file, $file . '.bak' );
					// Remove suspicious code
					$cleaned = preg_replace( '/(eval|document\.write|unescape)\s*\([^)]+\);?/', '', $content );
					file_put_contents( $file, $cleaned );
				}
			}
		}
	}

	private function scan_database( &$results ) {
		global $wpdb;

		// Check posts and postmeta
		$suspicious_content = $wpdb->get_results(
			"SELECT ID, post_content FROM {$wpdb->posts} 
            WHERE post_content LIKE '%eval%' 
            OR post_content LIKE '%base64_decode%'
            OR post_content LIKE '%document.write%'"
		);

		foreach ( $suspicious_content as $post ) {
			$results['db_infections'][] = array(
				'type' => 'post',
				'id'   => $post->ID,
			);
			// Clean post content
			$wpdb->update(
				$wpdb->posts,
				array( 'post_content' => $this->clean_content( $post->post_content ) ),
				array( 'ID' => $post->ID )
			);
		}

		// Check options table
		$suspicious_options = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options}
            WHERE option_value LIKE '%eval%'
            OR option_value LIKE '%base64_decode%'
            OR option_value LIKE '%document.write%'"
		);

		foreach ( $suspicious_options as $option ) {
			$results['db_infections'][] = array(
				'type' => 'option',
				'name' => $option->option_name,
			);
			// Clean option value
			update_option( $option->option_name, $this->clean_content( $option->option_value ) );
		}
	}

	private function clean_content( $content ) {
		// Remove eval and base64 code
		$content = preg_replace( '/eval\s*\([^)]+\);?/', '', $content );
		$content = preg_replace( '/base64_decode\s*\([^)]+\);?/', '', $content );
		// Remove suspicious JavaScript
		$content = preg_replace( '/<script[^>]*>(.*?)<\/script>/is', '', $content );
		return $content;
	}

	private function clean_infections( $results ) {
		// Remove zero-byte files
		foreach ( $results['zero_byte_files'] as $file ) {
			unlink( $file );
			$this->logger->info( "Removed zero-byte file: $file" );
		}

		// Clean suspicious files
		foreach ( $results['suspicious_files'] as $file ) {
			unlink( $file );
			$this->logger->info( "Removed suspicious file: $file" );
		}

		$this->logger->info(
			'Infection cleanup completed',
			array(
				'zero_byte_files'  => count( $results['zero_byte_files'] ),
				'suspicious_files' => count( $results['suspicious_files'] ),
				'js_infections'    => count( $results['js_infections'] ),
				'db_infections'    => count( $results['db_infections'] ),
			)
		);
	}
}
