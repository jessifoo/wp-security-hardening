<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP_Security_Settings {
	private static $instance = null;
	private $options;
	private $option_name = 'wp_security_settings';

	private function __construct() {
		$this->options = get_option( $this->option_name, $this->get_defaults() );
	}

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function get_defaults() {
		return array(
			'scan_schedule' => 'daily',
			'scan_time'     => '00:00',
			'auto_clean'    => true,
			'notify_admin'  => true,
			'log_level'     => 'warning',
		);
	}

	public function get( $key ) {
		return isset( $this->options[ $key ] ) ? $this->options[ $key ] : null;
	}

	public function set( $key, $value ) {
		$this->options[ $key ] = $value;
		return update_option( $this->option_name, $this->options );
	}

	public function get_all() {
		return $this->options;
	}
}
