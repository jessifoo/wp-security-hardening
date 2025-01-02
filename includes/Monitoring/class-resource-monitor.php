<?php
/**
 * Smart API Usage Manager
 * Optimizes API usage through batching and smart scanning
 */

class WP_Security_Resource_Monitor {
	private $sites = array(
		'jessica-johnson.ca',
		'rayzgyproc.com',
		'spectrapsychology.com',
	);

	private $daily_limit = 500; // VirusTotal free tier daily limit
	private $batch_size  = 100;  // Maximum files per VirusTotal API call

	/**
	 * Queue files for scanning
	 * Returns batch ID if queued, false if should skip
	 */
	public function queue_for_scan( $files ) {
		$files_to_scan = array();

		foreach ( $files as $file ) {
			// Skip if file hasn't changed and was previously verified
			if ( $this->is_file_verified( $file ) ) {
				continue;
			}
			$files_to_scan[] = $file;
		}

		if ( empty( $files_to_scan ) ) {
			return false;
		}

		// Create batches based on available API calls
		$available_calls = $this->get_remaining_calls();
		$total_batches   = ceil( count( $files_to_scan ) / $this->batch_size );

		if ( $total_batches > $available_calls ) {
			// Prioritize newest/modified files if we can't scan everything
			usort(
				$files_to_scan,
				function ( $a, $b ) {
					return filemtime( $b ) - filemtime( $a );
				}
			);
			$files_to_scan = array_slice( $files_to_scan, 0, $available_calls * $this->batch_size );
		}

		if ( ! empty( $files_to_scan ) ) {
			$batch_id = uniqid( 'scan_' );
			set_transient( 'wp_security_scan_batch_' . $batch_id, $files_to_scan, DAY_IN_SECONDS );
			return $batch_id;
		}

		return false;
	}

	/**
	 * Check if file needs scanning
	 */
	private function is_file_verified( $file ) {
		$hash          = md5_file( $file );
		$last_verified = get_transient( 'wp_security_verified_' . $hash );

		if ( $last_verified ) {
			$file_time = filemtime( $file );
			// If file unchanged since last verification and within same version
			if ( $file_time <= $last_verified['time'] &&
				$last_verified['wp_version'] === get_bloginfo( 'version' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Mark files as verified
	 */
	public function mark_files_verified( $files ) {
		foreach ( $files as $file ) {
			$hash = md5_file( $file );
			set_transient(
				'wp_security_verified_' . $hash,
				array(
					'time'       => time(),
					'wp_version' => get_bloginfo( 'version' ),
				),
				WEEK_IN_SECONDS
			);
		}
	}

	/**
	 * Get next batch of files to scan
	 */
	public function get_scan_batch( $batch_id ) {
		$files = get_transient( 'wp_security_scan_batch_' . $batch_id );
		if ( ! $files ) {
			return false;
		}

		$batch = array_splice( $files, 0, $this->batch_size );

		if ( ! empty( $files ) ) {
			// Store remaining files
			set_transient( 'wp_security_scan_batch_' . $batch_id, $files, DAY_IN_SECONDS );
		} else {
			delete_transient( 'wp_security_scan_batch_' . $batch_id );
		}

		return $batch;
	}

	/**
	 * Get remaining API calls for today
	 */
	private function get_remaining_calls() {
		$per_site_limit = $this->daily_limit / count( $this->sites );
		$used           = get_transient( 'wp_security_api_calls' ) ?: 0;
		return max( 0, floor( $per_site_limit - $used ) );
	}

	/**
	 * Log successful API call
	 */
	public function log_api_call() {
		$used = get_transient( 'wp_security_api_calls' ) ?: 0;
		set_transient( 'wp_security_api_calls', $used + 1, DAY_IN_SECONDS );
	}
}
