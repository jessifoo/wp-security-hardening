<?php

namespace WP_Security\Scanner;

use WP_Security\Core\Logger\LoggerInterface;
use WP_Security\Scanner\Malware\MalwareDetector;
use WP_Security\Monitoring\Resource\ResourceManager;
use WP_Security\Monitoring\Resource\Exception\ResourceLimitException;

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

/**
 * Manages and orchestrates different scanning operations
 */
class ScanManager {
	/** @var MalwareDetector */
	private $malwareDetector;

	/** @var ResourceManager */
	private $resourceManager;

	/** @var LoggerInterface */
	private $logger;

	/**
	 * Constructor
	 *
	 * @param MalwareDetector $malwareDetector Malware detector instance
	 * @param ResourceManager $resourceManager Resource manager instance
	 * @param LoggerInterface $logger Logger instance
	 */
	public function __construct( MalwareDetector $malwareDetector, ResourceManager $resourceManager, LoggerInterface $logger ) {
		$this->malwareDetector = $malwareDetector;
		$this->resourceManager = $resourceManager;
		$this->logger          = $logger;
	}

	/**
	 * Run all scans
	 *
	 * @return array Results of all scans
	 */
	public function runScans() {
		// Allow other plugins to modify scan configuration
		$scan_config = apply_filters(
			'wp_security_scan_config',
			array(
				'scan_core'    => true,
				'scan_plugins' => true,
				'scan_themes'  => true,
				'scan_uploads' => true,
			)
		);

		// Action before scan starts
		do_action( 'wp_security_before_scan', $scan_config );

		try {
			$results = array();

			if ( $scan_config['scan_core'] ) {
				$results['core'] = $this->malwareDetector->scanCore();
			}

			if ( $scan_config['scan_plugins'] ) {
				$results['plugins'] = $this->malwareDetector->scanPlugins();
			}

			if ( $scan_config['scan_themes'] ) {
				$results['themes'] = $this->malwareDetector->scanThemes();
			}

			if ( $scan_config['scan_uploads'] ) {
				$results['uploads'] = $this->malwareDetector->scanUploads();
			}

			// Allow other plugins to modify scan results
			$results = apply_filters( 'wp_security_scan_results', $results );

			// Action after scan completes
			do_action( 'wp_security_after_scan', $results );

			return $results;

		} catch ( ResourceLimitException $e ) {
			$this->logger->warning(
				'Scan interrupted due to resource limits',
				array(
					'error'          => $e->getMessage(),
					'resource_usage' => $this->resourceManager->getUsage(),
				)
			);
		} catch ( \Exception $e ) {
			$this->logger->error( 'Scan failed: ' . $e->getMessage() );
			do_action( 'wp_security_scan_error', $e );
			throw $e;
		}
	}
}
