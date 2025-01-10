<?php
namespace WP_Security\Security;

class RateLimiter {
	private $wpdb;

	public function __construct() {
		global $wpdb;
		$this->wpdb = $wpdb;
	}

	public function checkLimit( $key, $period, $max_attempts = 10 ): bool {
		$table = $this->wpdb->prefix . 'security_rate_limits';
		$now   = current_time( 'mysql' );

		// Clean old entries
		$this->wpdb->query(
			$this->wpdb->prepare(
				"DELETE FROM $table WHERE reset_at < %s",
				$now
			)
		);

		// Check current count
		$current = $this->wpdb->get_row(
			$this->wpdb->prepare(
				"SELECT * FROM $table WHERE rate_key = %s",
				$key
			)
		);

		if ( ! $current ) {
			// First attempt
			$this->wpdb->insert(
				$table,
				array(
					'rate_key' => $key,
					'count'    => 1,
					'reset_at' => date( 'Y-m-d H:i:s', strtotime( "+$period seconds" ) ),
				)
			);
			return true;
		}

		if ( $current->count >= $max_attempts ) {
			return false;
		}

		// Increment counter
		$this->wpdb->update(
			$table,
			array( 'count' => $current->count + 1 ),
			array( 'rate_key' => $key )
		);

		return true;
	}
}
