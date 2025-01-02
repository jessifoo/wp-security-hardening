<?php

namespace WP_Security\Monitoring\Resource;

use WP_Security\Core\Logger\LoggerInterface;
use WP_Security\Monitoring\Resource\Exception\ResourceLimitException;

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

/**
 * Manages resource monitoring and limits for WordPress operations
 *
 * Responsibilities:
 * - Monitor system resource usage
 * - Enforce configurable resource limits
 * - Provide optimal batch sizes for operations
 * - Integrate with WordPress options API
 */
class ResourceManager {
	/** @var LoggerInterface */
	private $logger;

	/** @var array */
	private $limits;

	/** @var array */
	private $usage_stats;

	/**
	 * Constructor
	 *
	 * @param LoggerInterface $logger Logger instance
	 */
	public function __construct( LoggerInterface $logger ) {
		$this->logger      = $logger;
		$this->limits      = $this->get_default_limits();
		$this->usage_stats = array();
	}

	/**
	 * Get default resource limits
	 *
	 * @return array Default limits
	 */
	private function get_default_limits(): array {
		return array(
			'memory'   => array(
				'max'     => 128 * 1024 * 1024, // 128MB for Hostinger compatibility
				'warning' => 100 * 1024 * 1024,
			),
			'time'     => array(
				'max'     => 180, // 3 minutes max
				'warning' => 150,
			),
			'files'    => array(
				'max'   => 5000,
				'size'  => 5 * 1024 * 1024, // 5MB max file size
				'batch' => 500,
			),
			'database' => array(
				'batch' => 1000,
				'pause' => 1, // 1 second pause between batches
			),
		);
	}

	/**
	 * Check if current resource usage exceeds limits
	 *
	 * @param array $metrics Current resource metrics
	 * @throws ResourceLimitException If limits are exceeded
	 */
	public function check( array $metrics ): void {
		$this->update_usage_stats( $metrics );

		if ( isset( $metrics['memory'] ) && $metrics['memory'] > $this->limits['memory']['max'] ) {
			throw new ResourceLimitException(
				'Memory limit exceeded',
				ResourceLimitException::MEMORY_LIMIT_EXCEEDED
			);
		}

		if ( isset( $metrics['time'] ) && $metrics['time'] > $this->limits['time']['max'] ) {
			throw new ResourceLimitException(
				'Time limit exceeded',
				ResourceLimitException::TIME_LIMIT_EXCEEDED
			);
		}

		if ( isset( $metrics['files_processed'] ) && $metrics['files_processed'] > $this->limits['files']['max'] ) {
			throw new ResourceLimitException(
				'File limit exceeded',
				ResourceLimitException::FILE_LIMIT_EXCEEDED
			);
		}

		// If approaching limits, trigger garbage collection
		if ( $this->is_approaching_limits() ) {
			$this->optimize_resources();
		}
	}

	/**
	 * Get optimal batch size based on current resource usage
	 *
	 * @param string $resource Type of resource (files, database)
	 * @return int Optimal batch size
	 */
	public function getOptimalBatchSize( string $resource = 'files' ): int {
		$memory_usage = memory_get_usage( true );
		$memory_limit = $this->limits['memory']['max'];
		$memory_ratio = $memory_usage / $memory_limit;

		// Adjust batch size based on memory usage
		$base_size     = $resource === 'files' ? $this->limits['files']['batch'] : $this->limits['database']['batch'];
		$adjusted_size = (int) ( $base_size * ( 1 - $memory_ratio ) );

		return max( $adjusted_size, 100 ); // Minimum batch size of 100
	}

	/**
	 * Get current resource usage statistics
	 *
	 * @return array Resource usage statistics
	 */
	public function getUsage(): array {
		return $this->usage_stats;
	}

	/**
	 * Update internal usage statistics
	 *
	 * @param array $metrics Current metrics
	 */
	private function update_usage_stats( array $metrics ): void {
		$this->usage_stats                = array_merge( $this->usage_stats, $metrics );
		$this->usage_stats['peak_memory'] = memory_get_peak_usage( true );
	}

	/**
	 * Check if approaching resource limits
	 *
	 * @return bool True if approaching limits
	 */
	private function is_approaching_limits(): bool {
		$memory_usage = memory_get_usage( true );
		return $memory_usage > $this->limits['memory']['warning'];
	}

	/**
	 * Optimize resource usage
	 */
	private function optimize_resources(): void {
		if ( function_exists( 'gc_collect_cycles' ) ) {
			gc_collect_cycles();
		}
		$this->logger->debug(
			'Resource optimization performed',
			array(
				'memory_before' => memory_get_usage( true ),
				'memory_after'  => memory_get_usage( true ),
			)
		);
	}

	/**
	 * Check database resource usage
	 *
	 * @param array $metrics Database metrics
	 */
	public function checkDatabase( array $metrics ): void {
		global $wpdb;

		// Set MySQL session variables for optimization
		$wpdb->query( 'SET SESSION wait_timeout = 180' ); // 3 minutes
		$wpdb->query( 'SET SESSION max_execution_time = 180000' ); // 3 minutes in milliseconds

		$this->check( $metrics );

		// Add small pause between batches to prevent overload
		if ( isset( $metrics['rows_processed'] ) && $metrics['rows_processed'] > 0 ) {
			usleep( $this->limits['database']['pause'] * 1000000 );
		}
	}
}
