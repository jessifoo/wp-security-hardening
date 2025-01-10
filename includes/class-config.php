<?php
namespace WP_Security;

class Config {
	private $config = array();

	public function __construct() {
		$this->config = array(
			'scan'     => array(
				'intervals'        => array( 'hourly', 'daily', 'weekly' ),
				'default_interval' => 'daily',
				'batch_size'       => 100,
			),
			'api'      => array(
				'rate_limits' => array(
					'scan'  => 100,
					'clean' => 50,
				),
				'timeout'     => 30,
			),
			'security' => array(
				'min_password_length' => 12,
				'password_complexity' => true,
				'login_attempts'      => 5,
				'lockout_duration'    => 900,
			),
		);
	}

	public function get( $key, $default = null ) {
		return $this->dot_get( $this->config, $key, $default );
	}

	private function dot_get( array $array, $key, $default = null ) {
		if ( isset( $array[ $key ] ) ) {
			return $array[ $key ];
		}

		foreach ( explode( '.', $key ) as $segment ) {
			if ( ! is_array( $array ) || ! array_key_exists( $segment, $array ) ) {
				return $default;
			}
			$array = $array[ $segment ];
		}

		return $array;
	}
}
