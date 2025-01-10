<?php

/**
 * PHPUnit bootstrap file
 */

// First, load Composer's autoloader
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// Then, we need to load WordPress test environment
$_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

// Load WordPress test environment
require_once $_tests_dir . '/includes/functions.php';
require_once $_tests_dir . '/includes/bootstrap.php';
