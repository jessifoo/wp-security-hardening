<?php

namespace WP_Security\Monitoring\Resource\Interface;

/**
 * Interface for resource monitoring components
 */
interface ResourceMonitorInterface {
	/**
	 * Check current resource usage
	 *
	 * @param array $metrics Current resource metrics to check
	 * @return array Resource status and metrics
	 */
	public function check( array $metrics ): array;

	/**
	 * Get current resource usage statistics
	 *
	 * @return array Resource usage statistics
	 */
	public function getUsage(): array;

	/**
	 * Get optimal batch size for operations
	 *
	 * @param string $resource Type of resource (memory, files, db)
	 * @return int Recommended batch size
	 */
	public function getOptimalBatchSize( string $resource ): int;
}
