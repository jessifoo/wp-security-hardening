<?php

namespace WP_Security\Security\Scanner;

use WP_Security\Core\Logger\LoggerInterface;
use WP_Security\Core\ResourceManager;
use WP_Security\Security\FileSystem\FileSystemInterface;
use WP_Security\Events\SecurityEvent;
use WP_Security\Security\QuarantineManager;
use WP_Security\Security\Yara\YaraScanner;

class ScanManager {
	private LoggerInterface $logger;
	private ResourceManager $resource_manager;
	private FileSystemInterface $file_system;
	private QuarantineManager $quarantine_manager;
	private YaraScanner $yara_scanner;

	public function __construct(
		LoggerInterface $logger,
		ResourceManager $resource_manager,
		FileSystemInterface $file_system,
		QuarantineManager $quarantine_manager,
		YaraScanner $yara_scanner
	) {
		$this->logger             = $logger;
		$this->resource_manager   = $resource_manager;
		$this->file_system        = $file_system;
		$this->quarantine_manager = $quarantine_manager;
		$this->yara_scanner       = $yara_scanner;
	}

	public function scan( array $options = array() ): ScanResultInterface {
		// Keep existing scan configuration
		$scan_config = wp_parse_args(
			$options,
			array(
				'scan_core'          => true,
				'scan_plugins'       => true,
				'scan_themes'        => true,
				'scan_uploads'       => true,
				'clean_infected'     => true,
				'quarantine_threats' => true,
			)
		);

		// Allow plugins to modify scan configuration
		$scan_config = apply_filters( 'wp_security_scan_config', $scan_config );

		try {
			$this->checkResourceLimits();

			// Action before scan starts
			do_action( 'wp_security_before_scan', $scan_config );

			// Perform scan with resource-aware batching
			$results = $this->performScan( $scan_config );

			// Handle threats with improved logging and quarantine
			foreach ( $results->getThreats() as $threat ) {
				$this->handleThreat( $threat, $scan_config );
			}

			// Action after scan completes
			do_action( 'wp_security_after_scan', $results );

			return $results;

		} catch ( \Exception $e ) {
			$this->logger->error(
				'Scan failed',
				array(
					'error' => $e->getMessage(),
					'trace' => $e->getTraceAsString(),
				)
			);
			throw $e;
		}
	}

	private function performScan( array $config ): ScanResultInterface {
		$result = new ScanResult();

		// Get all files to scan based on config
		$files = $this->getFilesToScan( $config );

		// Process files in batches
		$this->processBatch(
			$files,
			function ( $file ) use ( $result ) {
				// Basic file scan
				$scan_result = $this->file_system->scanFile( $file );
				if ( ! empty( $scan_result ) ) {
					$result->addThreat( 'file', $file, $scan_result );
				}

				// YARA scan
				$yara_result = $this->yara_scanner->scan( $file );
				if ( ! empty( $yara_result ) ) {
					$result->addThreat( 'yara', $file, $yara_result );
				}

				// Zero-byte check
				if ( filesize( $file ) === 0 && pathinfo( $file, PATHINFO_EXTENSION ) === 'php' ) {
					$result->addThreat( 'zero_byte', $file, array( 'type' => 'zero_byte' ) );
				}
			}
		);

		return $result;
	}

	private function handleThreat( $threat, array $config ): void {
		// Dispatch security event
		$event = new SecurityEvent(
			'threat_detected',
			$threat->getSeverity(),
			$threat->getContext()
		);
		$this->event_dispatcher->dispatch( $event );

		// Quarantine if needed
		if ( $config['quarantine_threats'] && $threat->requiresQuarantine() ) {
			$this->quarantine_manager->quarantineFile(
				$threat->getFile(),
				$threat->getType()
			);
		}

		// Clean if enabled
		if ( $config['clean_infected'] ) {
			try {
				$this->cleanInfectedFile( $threat );
			} catch ( \Exception $e ) {
				$this->logger->error(
					'Failed to clean infected file',
					array(
						'file'  => $threat->getFile(),
						'error' => $e->getMessage(),
					)
				);
			}
		}
	}

	private function getFilesToScan( array $config ): array {
		$files = array();

		if ( $config['scan_core'] ) {
			$files = array_merge( $files, $this->getCoreFiles() );
		}

		if ( $config['scan_plugins'] ) {
			$files = array_merge( $files, $this->getPluginFiles() );
		}

		// etc...

		return array_unique( $files );
	}

	private function getCoreFiles(): array {
		return array_merge(
			glob( ABSPATH . '*.php' ),
			glob( ABSPATH . 'wp-admin/*.php' ),
			glob( ABSPATH . 'wp-includes/*.php' )
		);
	}

	private function getPluginFiles(): array {
		return $this->file_system->listFiles( WP_PLUGIN_DIR, array( 'php' ) );
	}

	private function getThemeFiles(): array {
		return $this->file_system->listFiles( get_theme_root(), array( 'php' ) );
	}

	private function getUploadFiles(): array {
		$upload_dir = wp_upload_dir();
		return $this->file_system->listFiles( $upload_dir['basedir'], array( 'php' ) );
	}

	private function processBatch( array $files, callable $callback ): void {
		$batch_size = $this->resource_manager->getOptimalBatchSize( 'files' );
		$chunks     = array_chunk( $files, $batch_size );

		foreach ( $chunks as $chunk ) {
			if ( $this->resource_manager->shouldPause() ) {
				$this->logger->info( 'Scan paused due to resource constraints' );
				break;
			}

			foreach ( $chunk as $file ) {
				try {
					$callback( $file );
				} catch ( \Exception $e ) {
					$this->logger->error(
						'File processing failed',
						array(
							'file'  => $file,
							'error' => $e->getMessage(),
						)
					);
				}
			}

			wp_pause_execution();
		}
	}
}
