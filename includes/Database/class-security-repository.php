<?php
namespace WP_Security\Database;

class SecurityRepository {
	private $wpdb;

	public function __construct() {
		global $wpdb;
		$this->wpdb = $wpdb;
	}

	public function logThreat( $threat ) {
		return $this->wpdb->insert(
			$this->wpdb->prefix . 'security_threats',
			array(
				'type'        => $threat['type'],
				'severity'    => $threat['severity'],
				'description' => $threat['description'],
				'file_path'   => $threat['file_path'] ?? '',
				'created_at'  => current_time( 'mysql' ),
			)
		);
	}
}
