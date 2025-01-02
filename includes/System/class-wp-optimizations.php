/**
* WP Security Hardening Plugin - WordPress Optimizations Class
*
* This class handles WordPress optimizations and performance improvements
* for better security and efficiency.
*
* @package WP_Security_Hardening
* @since 1.0.0
*/

class WP_Security_WP_Optimizations {
/** @var array List of high-risk directories to monitor. */
private $high_risk_dirs;

/** @var array List of critical files to protect. */
private $critical_files;

/** @var array List of safe functions allowed in the codebase. */
private $safe_functions;

/** @var array List of unsafe functions to monitor. */
private $unsafe_functions;

/**
* Constructor - Initialize optimization settings and directories.
*
* @since 1.0.0
*/
public function __construct() {
$this->init_directories();
}

/**
* Initialize critical directories and files for monitoring.
*
* @since 1.0.0
*/
private function init_directories() {
// Set up monitoring directories
$this->high_risk_dirs = array(
WP_CONTENT_DIR . '/uploads',
WP_CONTENT_DIR . '/cache',
WP_CONTENT_DIR . '/upgrade'
);
}

/**
* Run WordPress optimizations for better security and performance.
*
* @since 1.0.0
*/
public function optimize_wordpress() {
// Disable features that could be security risks
$this->disable_wp_cron();

// Optimize WordPress database and settings
$this->optimize_wp_options();
$this->optimize_wp_queries();

// Clean up unnecessary data
$this->disable_wp_revisions();
$this->cleanup_transients();
}

/**
* Disable WordPress cron for better control over scheduled tasks.
*
* @since 1.0.0
*/
private function disable_wp_cron() {
if (!defined('DISABLE_WP_CRON')) {
define('DISABLE_WP_CRON', true);
}
}

/**
* Optimize WordPress options table.
*
* @since 1.0.0
*/
public function optimize_wp_options() {
// Remove unused options
delete_option('can_compress_scripts');

// Disable pingbacks
update_option('default_pingback_flag', 0);

// Limit post revisions
if (!defined('WP_POST_REVISIONS')) {
define('WP_POST_REVISIONS', 5);
}
}

/**
* Optimize WordPress database queries.
*
* @since 1.0.0
*/
public function optimize_wp_queries() {
global $wpdb;

// Use caching for database queries
wp_cache_add_global_groups(['security_queries']);

// Clean up post meta
$wpdb->query("DELETE FROM $wpdb->postmeta WHERE post_id NOT IN (SELECT ID FROM $wpdb->posts)");
wp_cache_flush();
}

/**
* Get list of high-risk directories that need monitoring.
*
* @since 1.0.0
* @return array List of high-risk directory paths
*/
public function get_high_risk_directories() {
return array_merge($this->high_risk_dirs, array(
get_template_directory(),
WP_CONTENT_DIR . '/plugins',
WP_CONTENT_DIR . '/mu-plugins',
WP_CONTENT_DIR . '/uploads',
ABSPATH . 'wp-admin',
ABSPATH . 'wp-includes'
));
}

/**
* Get list of critical WordPress files to monitor.
*
* @since 1.0.0
* @return array List of critical file paths
*/
public function get_critical_files() {
return array(
ABSPATH . 'wp-config.php',
ABSPATH . '.htaccess',
ABSPATH . 'index.php',
ABSPATH . 'wp-settings.php',
ABSPATH . 'wp-load.php',
ABSPATH . 'wp-blog-header.php'
);
}

/**
* Check if a file is a WordPress core file.
*
* @since 1.0.0
* @param string $file Path to the file
* @return bool True if core file, false otherwise
*/
public function is_core_file($file) {
$core_paths = array(
ABSPATH . 'wp-admin/',
ABSPATH . 'wp-includes/'
);
return in_array($file, $core_paths, true);
}

/**
* Get list of functions considered safe.
*
* @since 1.0.0
* @return array List of safe function names
*/
public function get_safe_functions() {
return array(
'wp_kses',
'esc_html',
'esc_url',
'esc_js',
'esc_attr',
'sanitize_text_field',
'sanitize_email',
'wp_verify_nonce',
'check_admin_referer',
'wp_create_nonce'
);
}

/**
* Get list of potentially unsafe functions to monitor.
*
* @since 1.0.0
* @return array List of unsafe function names
*/
public function get_unsafe_functions() {
return array(
'eval',
'base64_decode',
'gzinflate',
'gzuncompress',
'system',
'exec',
'shell_exec',
'passthru',
'proc_open',
'popen',
'curl_exec',
'curl_multi_exec',
'parse_str',
'extract',
'putenv'
);
}

/**
* Optimize WordPress environment for security scanning.
*
* @since 1.0.0
*/
public function optimize_for_scan() {
// Increase memory limit for scan
if (!defined('WP_MEMORY_LIMIT')) {
define('WP_MEMORY_LIMIT', '256M');
}

// Increase time limit for thorough scan
set_time_limit(300);

// Disable potentially interfering plugins
$this->disable_security_plugins();
}

/**
* Disable other security plugins during scan.
*
* @since 1.0.0
*/
private function disable_security_plugins() {
$security_plugins = array(
'wordfence/wordfence.php',
'better-wp-security/better-wp-security.php',
'sucuri-scanner/sucuri.php',
'all-in-one-wp-security-and-firewall/wp-security.php'
);

$this->temporarily_disable_plugins($security_plugins);
}

/**
* Disable caching plugins during scan.
*
* @since 1.0.0
*/
private function disable_caching_plugins() {
$caching_plugins = array(
'wp-super-cache/wp-cache.php',
'w3-total-cache/w3-total-cache.php',
'wp-fastest-cache/wpFastestCache.php'
);

$this->temporarily_disable_plugins($caching_plugins);
}

/**
* Disable backup plugins during scan.
*
* @since 1.0.0
*/
private function disable_backup_plugins() {
$backup_plugins = array(
'updraftplus/updraftplus.php',
'backwpup/backwpup.php',
'duplicator/duplicator.php'
);

$this->temporarily_disable_plugins($backup_plugins);
}

/**
* Temporarily disable specified plugins.
*
* @since 1.0.0
* @param array $plugins List of plugin paths to disable
*/
private function temporarily_disable_plugins($plugins) {
if (!is_array(get_option('active_plugins'))) {
return;
}

$active_plugins = get_option('active_plugins');
$this->backup_active_plugins($active_plugins);

foreach ($plugins as $plugin) {
if (($key = array_search($plugin, $active_plugins, true)) !== false) {
unset($active_plugins[$key]);
}
}

update_option('active_plugins', $active_plugins);
}

/**
* Restore previously disabled plugins.
*
* @since 1.0.0
*/
public function restore_plugins() {
$backup = get_option('wp_security_plugin_backup');
if ($backup) {
update_option('active_plugins', $backup);
delete_option('wp_security_plugin_backup');
}
}

/**
* Get plugin information by its file hash.
*
* @since 1.0.0
* @param string $hash SHA-256 hash of the plugin file
* @return array|false Plugin information or false if not found
*/
public function get_plugin_by_hash($hash) {
if (!function_exists('get_plugins')) {
require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$plugins = get_plugins();
foreach ($plugins as $plugin_path => $plugin_data) {
$plugin_file = WP_PLUGIN_DIR . '/' . $plugin_path;
if (file_exists($plugin_file) && hash_file('sha256', $plugin_file) === $hash) {
return array(
'path' => $plugin_path,
'data' => $plugin_data
);
}
}

return false;
}

/**
* Clear all WordPress caches.
*
* @since 1.0.0
*/
public function clear_caches() {
// Clear WordPress object cache
wp_cache_flush();

// Clear transients
$this->cleanup_transients();

// Clear rewrite rules
flush_rewrite_rules();

// Clear other caches if present
if (function_exists('w3tc_flush_all')) {
w3tc_flush_all();
}
}

/**
* Restore WordPress environment after scan.
*
* @since 1.0.0
*/
public function restore_environment() {
// Restore original memory limit
if (defined('WP_MEMORY_LIMIT')) {
ini_set('memory_limit', WP_MEMORY_LIMIT);
}

// Restore time limit
set_time_limit(30);

// Re-enable plugins
$this->restore_plugins();
}

/**
* Restore WordPress settings after optimization.
*
* @since 1.0.0
*/
private function restore_wp_settings() {
// Restore original cron settings
if (defined('DISABLE_WP_CRON')) {
update_option('disable_wp_cron', false);
}

// Restore revision settings
if (defined('WP_POST_REVISIONS')) {
update_option('wp_post_revisions', true);
}
}
}