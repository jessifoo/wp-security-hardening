<?php
/**
 * Performance profiling functionality
 *
 * @package WP_Security_Hardening
 */

/**
 * Class WP_Security_Performance_Profiler
 *
 * Handles performance profiling and monitoring for the security plugin.
 */
class WP_Security_Performance_Profiler {
	/**
	 * Stores timing data for different operations
	 *
	 * @var array
	 */
	private static $timings = array();

	/**
	 * Stores memory usage data
	 *
	 * @var array
	 */
	private static $memory_usage = array();

	/**
	 * Stores query data when SAVEQUERIES is enabled
	 *
	 * @var array
	 */
	private static $queries = array();

	/**
	 * Start timing an operation
	 *
	 * @param string $operation Name of the operation to time.
	 * @return void
	 */
	public static function start_timing( $operation ) {
		if ( ! defined( 'WP_SECURITY_PROFILE' ) || ! WP_SECURITY_PROFILE ) {
			return;
		}

		self::$timings[ $operation ] = array(
			'start'        => microtime( true ),
			'memory_start' => memory_get_usage(),
		);
	}

	/**
	 * End timing an operation and log the results
	 *
	 * @param string $operation Name of the operation to stop timing.
	 * @return void
	 */
	public static function end_timing( $operation ) {
		if ( ! defined( 'WP_SECURITY_PROFILE' ) || ! WP_SECURITY_PROFILE ) {
			return;
		}

		if ( ! isset( self::$timings[ $operation ] ) ) {
			return;
		}

		$end_time   = microtime( true );
		$end_memory = memory_get_usage();

		$duration = $end_time - self::$timings[ $operation ]['start'];
		$memory   = $end_memory - self::$timings[ $operation ]['memory_start'];

		self::$timings[ $operation ]['duration'] = $duration;
		self::$timings[ $operation ]['memory']   = $memory;

		if ( defined( 'WP_SECURITY_PROFILE_LOG' ) && WP_SECURITY_PROFILE_LOG ) {
			error_log(
				sprintf(
					'[Security Profile] %s - Time: %.4f sec, Memory: %.2f MB',
					$operation,
					$duration,
					$memory / 1024 / 1024
				)
			);
		}
	}

	/**
	 * Log database queries if SAVEQUERIES is enabled
	 *
	 * @return void
	 */
	public static function log_queries() {
		global $wpdb;

		if ( ! defined( 'SAVEQUERIES' ) || ! SAVEQUERIES ) {
			return;
		}

		self::$queries = array();
		foreach ( $wpdb->queries as $query ) {
			$sql   = $query[0];
			$time  = $query[1];
			$stack = $query[2];

			// Only log queries from our plugin
			if ( strpos( $stack, 'wp-security-hardening' ) !== false ) {
				self::$queries[] = array(
					'sql'   => $sql,
					'time'  => $time,
					'stack' => $stack,
				);
			}
		}
	}

	/**
	 * Get performance report
	 *
	 * @return array Performance data
	 */
	public static function get_report() {
		return array(
			'timings'        => self::$timings,
			'queries'        => self::$queries,
			'peak_memory'    => memory_get_peak_usage() / 1024 / 1024, // MB
			'current_memory' => memory_get_usage() / 1024 / 1024,   // MB
		);
	}

	/**
	 * Profile a callback function
	 *
	 * @param string   $operation Operation name.
	 * @param callable $callback  Function to profile.
	 * @param array    $args      Arguments for the callback.
	 * @return mixed Result of the callback
	 */
	public static function profile_callback( $operation, $callback, $args = array() ) {
		self::start_timing( $operation );
		$result = call_user_func_array( $callback, $args );
		self::end_timing( $operation );
		return $result;
	}

	/**
	 * Initialize Xdebug profiling if available
	 *
	 * @return void
	 */
	public static function init_xdebug() {
		if ( ! extension_loaded( 'xdebug' ) ) {
			return;
		}

		// Enable profiling only in development
		if ( defined( 'WP_DEVELOPMENT_MODE' ) && WP_DEVELOPMENT_MODE ) {
			ini_set( 'xdebug.mode', 'profile' );
			ini_set( 'xdebug.output_dir', WP_CONTENT_DIR . '/profiles' );
			ini_set( 'xdebug.profiler_output_name', 'cachegrind.out.%t.%p' );
		}
	}
}
