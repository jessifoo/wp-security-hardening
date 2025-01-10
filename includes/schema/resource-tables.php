<?php
namespace WP_Security\Schema;

class ResourceTables {
	public static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		// Security Events Table
		$sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}security_events (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			event_type varchar(50) NOT NULL,
			severity varchar(20) NOT NULL,
			description text NOT NULL,
			context longtext,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY severity (severity)
		) $charset_collate;";

		// Quarantine Table
		$sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}security_quarantine (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			file_path varchar(255) NOT NULL,
			original_path varchar(255) NOT NULL,
			file_hash varchar(64) NOT NULL,
			threat_type varchar(50) NOT NULL,
			encrypted tinyint(1) DEFAULT 0,
			metadata longtext,
			quarantined_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY file_hash (file_hash)
		) $charset_collate;";

		// Rate Limiting Table
		$sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}security_rate_limits (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			rate_key varchar(64) NOT NULL,
			count int NOT NULL DEFAULT 1,
			reset_at datetime NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY rate_key (rate_key)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		foreach ( $sql as $query ) {
			dbDelta( $query );
		}
	}
}
