<?php
/**
 * Autoloader class for the plugin.
 *
 * @package WP_Security_Hardening
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class WP_Security_Hardening_Autoloader
 *
 * Handles autoloading of plugin classes.
 */
class WP_Security_Hardening_Autoloader {

    /**
     * Register the autoloader.
     */
    public static function register() {
        spl_autoload_register( array( self::class, 'autoload' ) );
    }

    /**
     * Autoload WP_Security classes.
     *
     * @param string $class_name The name of the class to load.
     */
    public static function autoload( $class_name ) {
        // Only handle classes with our prefix
        if ( 0 !== strpos( $class_name, 'WP_Security_Hardening_' ) ) {
            return;
        }

        // Convert the class name to a file path
        $file_path = self::get_file_path_from_class_name( $class_name );

        // If the file exists, require it
        if ( file_exists( $file_path ) ) {
            require_once $file_path;
        }
    }

    /**
     * Convert class name to a file path.
     *
     * @param string $class_name The name of the class.
     * @return string The path to the class file.
     */
    private static function get_file_path_from_class_name( $class_name ) {
        // Remove the prefix
        $class_name = str_replace( 'WP_Security_Hardening_', '', $class_name );

        // Convert to lowercase and replace underscores with hyphens
        $file_name = strtolower( str_replace( '_', '-', $class_name ) );

        // Build the full path
        return WP_SECURITY_PLUGIN_DIR . 'includes/class-' . $file_name . '.php';
    }
}
