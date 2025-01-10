<?php

namespace WP_Security\Security\Scanner\FileSystem;

use WP_Security\Core\Logger\LoggerInterface;
use WP_Security\Security\Yara\YaraScanner;
use WP_Security\Security\Scanner\Results\Threat;

class FileScanner implements FileScannerInterface {
	private LoggerInterface $logger;
	private YaraScanner $yara_scanner;
	private array $patterns;

	public function __construct(
		LoggerInterface $logger,
		YaraScanner $yara_scanner
	) {
		$this->logger       = $logger;
		$this->yara_scanner = $yara_scanner;
		$this->patterns     = $this->loadPatterns();
	}

	private function loadPatterns(): array {
		return apply_filters(
			'wp_security_malware_patterns',
			require WP_SECURITY_PATH . '/config/patterns.php'
		);
	}

	public function findZeroByteFiles(): array {
		$results = array();

		try {
			// Check wp-content directory
			$results = array_merge(
				$results,
				$this->scanForZeroByteFiles( WP_CONTENT_DIR )
			);

			// Check uploads directory
			$upload_dir = wp_upload_dir();
			$results    = array_merge(
				$results,
				$this->scanForZeroByteFiles( $upload_dir['basedir'] )
			);
		} catch ( \Exception $e ) {
			$this->logger->error(
				'Zero byte file scan failed',
				array(
					'error' => $e->getMessage(),
				)
			);
		}

		return $results;
	}

	public function scan( $file ) {
		$threats = array();

		try {
			// 1. Zero-byte check (critical requirement)
			if ( $this->isZeroByteFile( $file ) ) {
				$threats[] = new Threat( 'zero_byte', $file, 'critical' );
			}

			// 2. YARA malware scanning
			$yara_threats = $this->yara_scanner->scan( $file );
			if ( ! empty( $yara_threats ) ) {
				$threats = array_merge( $threats, $yara_threats );
			}

			// 3. Pattern-based scanning
			$content_threats = $this->scanFileContent( $file );
			if ( ! empty( $content_threats ) ) {
				$threats = array_merge( $threats, $content_threats );
			}

			// 4. Check for obfuscated code
			if ( $this->containsObfuscatedCode( $file ) ) {
				$threats[] = new Threat( 'obfuscated_code', $file, 'high' );
			}
		} catch ( \Exception $e ) {
			$this->logger->error(
				'File scan failed',
				array(
					'file'  => $file,
					'error' => $e->getMessage(),
				)
			);
		}

		return $threats;
	}

	private function scanFileContent( string $file ): array {
		$threats = array();
		$content = file_get_contents( $file );

		foreach ( $this->patterns as $pattern => $info ) {
			if ( preg_match( $pattern, $content ) ) {
				$threats[] = new Threat(
					$info['type'],
					$file,
					$info['severity']
				);
			}
		}

		return $threats;
	}

	private function isZeroByteFile( string $file ): bool {
		return file_exists( $file ) && filesize( $file ) === 0 &&
			pathinfo( $file, PATHINFO_EXTENSION ) === 'php';
	}

	private function containsObfuscatedCode( string $file ): bool {
		$content = file_get_contents( $file );

		// Check for common obfuscation patterns
		$obfuscation_patterns = array(
			// Base64 encoded chunks
			'/base64_decode\s*\([^)]{100,}\)/',
			// Long encoded strings
			'/[\'"]((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?){100,}[\'"]/',
			// Packed JavaScript
			'/eval\s*\(\s*function\s*\(p,a,c,k,e,[rd]\)/',
			// Excessive string concatenation
			'/(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\.?\s*){10,}/',
			// Hidden eval variations
			'/\\\\x65\\\\x76\\\\x61\\\\x6C/',
		);

		foreach ( $obfuscation_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				$this->logger->warning(
					'Obfuscated code detected',
					array(
						'file'    => $file,
						'pattern' => $pattern,
					)
				);
				return true;
			}
		}

		// Check entropy for possible obfuscation
		if ( $this->calculateEntropy( $content ) > 5.7 ) {
			$this->logger->warning(
				'High entropy content detected',
				array(
					'file'    => $file,
					'entropy' => $this->calculateEntropy( $content ),
				)
			);
			return true;
		}

		return false;
	}

	private function calculateEntropy( string $content ): float {
		$frequencies = array_count_values( str_split( $content ) );
		$length      = strlen( $content );
		$entropy     = 0.0;

		foreach ( $frequencies as $count ) {
			$probability = $count / $length;
			$entropy    -= $probability * log( $probability, 2 );
		}

		return $entropy;
	}
}
