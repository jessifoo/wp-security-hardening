<?php
/**
 * Resource Monitoring Database Schema
 */
function wp_security_create_resource_tables() {
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();

	// Resource usage logs
	$table_logs = $wpdb->prefix . 'security_resource_logs';
	$sql_logs   = "CREATE TABLE IF NOT EXISTS $table_logs (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        timestamp datetime NOT NULL,
        memory_usage bigint(20) NOT NULL,
        memory_peak bigint(20) NOT NULL,
        cpu_load float NOT NULL,
        api_calls text NOT NULL,
        db_size bigint(20) NOT NULL,
        PRIMARY KEY  (id),
        KEY timestamp (timestamp)
    ) $charset_collate;";

	// API usage tracking
	$table_api = $wpdb->prefix . 'security_api_usage';
	$sql_api   = "CREATE TABLE IF NOT EXISTS $table_api (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        site varchar(255) NOT NULL,
        date date NOT NULL,
        virustotal_api int(11) NOT NULL DEFAULT 0,
        yara_scans int(11) NOT NULL DEFAULT 0,
        wp_api int(11) NOT NULL DEFAULT 0,
        PRIMARY KEY  (id),
        UNIQUE KEY site_date (site, date)
    ) $charset_collate;";

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql_logs );
	dbDelta( $sql_api );
}

function wp_security_drop_resource_tables() {
	global $wpdb;

	$tables = array(
		$wpdb->prefix . 'security_resource_logs',
		$wpdb->prefix . 'security_api_usage',
	);

	foreach ( $tables as $table ) {
		$wpdb->query( "DROP TABLE IF EXISTS $table" );
	}
}
