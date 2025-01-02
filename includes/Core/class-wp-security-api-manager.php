<?php
/**
 * API Manager Class
 *
 * Handles API rate limiting and usage tracking across multiple sites.
 *
 * @package WP_Security_Hardening
 * @subpackage Includes
 * @since 1.0.0
 * @version 1.0.0
 * @requires PHP 8.2
 * @requires WordPress 6.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_Security_Rate_Limiter' ) ) {
	require_once __DIR__ . '/class-rate-limiter.php';
}

if ( ! class_exists( 'WP_Security_API_Utils' ) ) {
	require_once __DIR__ . '/utils/class-api-utils.php';
}

/**
 * API Manager class for handling API requests and rate limiting.
 */
class WP_Security_API_Manager {
	/**
	 * Option name for storing API usage.
	 *
	 * @var string
	 */
	private $option_name;

	/**
	 * Sites to manage API limits for.
	 *
	 * @var array
	 */
	private $sites;

	/**
	 * Rate limiter instance.
	 *
	 * @var WP_Security_Rate_Limiter
	 */
	private $rate_limiter;

	/**
	 * Constructor.
	 *
	 * @param array $sites List of sites to manage.
	 */
	public function __construct( $sites = array() ) {
		$this->sites        = $sites;
		$this->rate_limiter = new WP_Security_Rate_Limiter();
		$this->option_name  = 'wp_security_api_usage';
		$this->init_usage_tracking();
	}

	/**
	 * Initialize usage tracking.
	 */
	private function init_usage_tracking() {
		if ( ! get_option( $this->option_name ) ) {
			$initial_usage = array(
				'scan'       => 0,
				'clean'      => 0,
				'analyze'    => 0,
				'last_reset' => time(),
			);
			update_option( $this->option_name, $initial_usage );
		}
	}

	/**
	 * Make API request with rate limiting.
	 *
	 * @param string $api_name API service name.
	 * @param string $url      Request URL.
	 * @param array  $args     Request arguments.
	 * @return array|WP_Error Response or error.
	 */
	protected function make_api_request( $api_name, $url, $args = array() ) {
		return WP_Security_API_Utils::make_request(
			$url,
			$args,
			$api_name,
			$this->get_current_site_url()
		);
	}

	/**
	 * Check if API request is allowed.
	 *
	 * @param string $api_name API service name.
	 * @return bool True if request is allowed.
	 */
	protected function can_make_request( $api_name ) {
		$metrics = $this->get_usage_metrics();
		if ( ! isset( $metrics[ $api_name ] ) ) {
			return false;
		}
		return $metrics[ $api_name ]['remaining'] > 0;
	}

	/**
	 * Get remaining API requests.
	 *
	 * @param string $api_name API service name.
	 * @return int Number of remaining requests.
	 */
	public function get_remaining_requests( $api_name ) {
		return WP_Security_API_Utils::get_remaining_requests( $api_name, $this->get_current_site_url() );
	}

	/**
	 * Record API usage.
	 *
	 * @param string $action The API action to record.
	 */
	public function record_api_usage( $action ) {
		$usage = get_option( $this->option_name );
		if ( isset( $usage[ $action ] ) ) {
			++$usage[ $action ];
			update_option( $this->option_name, $usage );
		}
	}

	/**
	 * Get API usage metrics.
	 *
	 * @return array API usage metrics.
	 */
	public function get_usage_metrics() {
		$usage  = get_option( $this->option_name );
		$limits = $this->get_action_limits();

		$metrics = array();
		foreach ( $usage as $action => $count ) {
			if ( 'last_reset' !== $action ) {
				$metrics[ $action ] = array(
					'used'      => $count,
					'limit'     => isset( $limits[ $action ] ) ? $limits[ $action ] : 0,
					'remaining' => isset( $limits[ $action ] ) ? $limits[ $action ] - $count : 0,
				);
			}
		}

		return $metrics;
	}

	/**
	 * Check API limits.
	 *
	 * @return array Status of API limits.
	 */
	public function check_limits() {
		$usage  = get_option( $this->option_name );
		$limits = $this->get_action_limits();

		$status = array();
		foreach ( $limits as $action => $limit ) {
			$status[ $action ] = array(
				'within_limit'  => $usage[ $action ] < $limit,
				'usage_percent' => ( $usage[ $action ] / $limit ) * 100,
			);
		}

		return $status;
	}

	/**
	 * Get action limits.
	 *
	 * @return array Action limits.
	 */
	private function get_action_limits() {
		$site_count = max( 1, count( $this->sites ) );

		return array(
			'scan'    => floor( 1000 / $site_count ),
			'clean'   => floor( 500 / $site_count ),
			'analyze' => floor( 2000 / $site_count ),
		);
	}

	/**
	 * Get current site URL.
	 *
	 * @return string Current site URL.
	 */
	private function get_current_site_url() {
		return get_site_url();
	}
}
