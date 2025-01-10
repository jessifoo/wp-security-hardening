<?php

/**
 * Anti-Malware Security and Brute-Force Firewall
 *
 * @package GOTMLS
 * @author Eli Scheetz
 * @version 4.23.73
 */

// If direct access, load safe mode
if (
	isset( $_SERVER['DOCUMENT_ROOT'] )
	&& ( $script_file = str_replace(
		$_SERVER['DOCUMENT_ROOT'],
		'',
		isset( $_SERVER['SCRIPT_FILENAME'] ) ? $_SERVER['SCRIPT_FILENAME'] : ( isset( $_SERVER['SCRIPT_NAME'] ) ? $_SERVER['SCRIPT_NAME'] : '' )
	) )
	&& strlen( $script_file ) > strlen( '/' . basename( __FILE__ ) )
	&& substr( __FILE__, -1 * strlen( $script_file ) ) == substr( $script_file, -1 * strlen( __FILE__ ) )
	|| ! ( function_exists( 'add_action' ) && function_exists( 'load_plugin_textdomain' ) )
) {
	require __DIR__ . '/safe-load/index.php';
} else {
	require_once __DIR__ . '/images/index.php';
}

/**
 * Install plugin and check version requirements
 */
function gotmls_install() {
	if (
		strpos( gotmls_get_version( 'URL' ), '&wp=' )
		&& version_compare( GOTMLS_wp_version, GOTMLS_require_version, '<' )
	) {
		die( gotmls_htmlspecialchars( GOTMLS_require_version_LANGUAGE . ', NOT version: ' . GOTMLS_wp_version ) );
	} else {
		delete_option( 'GOTMLS_definitions_array' );
	}
}
register_activation_hook( __FILE__, 'gotmls_install' );

/**
 * Uninstall plugin and clean up options
 */
function gotmls_uninstall() {
	delete_option( 'GOTMLS_get_URL_array' );
	delete_option( 'GOTMLS_definitions_blob' );
	gotmls_create_session_file( false );
}
register_deactivation_hook( __FILE__, 'gotmls_uninstall' );
