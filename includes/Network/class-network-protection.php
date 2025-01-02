/**
 * Handles login security, IP blocking, and network protection
 */

namespace WP_Security\Network;

use WP_Security\Utils\{Utils, Logger};

if (!defined('ABSPATH')) {
    exit;
}

class Network_Protection {
    private $logger;
    private $options_prefix = 'wp_security_network_';
    private $max_attempts = 5;
    private $block_duration = 3600; // 1 hour
    private $whitelist = [];
    private $blacklist = [];

    public function __construct() {
        $this->logger = Logger::get_instance();
        
        // Load whitelists and blacklists
        $this->whitelist = get_option($this->options_prefix . 'whitelist', []);
        $this->blacklist = get_option($this->options_prefix . 'blacklist', []);

        // Add hooks
        add_filter('authenticate', [$this, 'check_login_attempt'], 30, 3);
        add_action('wp_login_failed', [$this, 'handle_failed_login']);
        add_action('wp_login', [$this, 'handle_successful_login'], 10, 2);
        
        // Cleanup old records daily
        if (!wp_next_scheduled('wp_security_cleanup_login_attempts')) {
            wp_schedule_event(time(), 'daily', 'wp_security_cleanup_login_attempts');
        }
        add_action('wp_security_cleanup_login_attempts', [$this, 'cleanup_old_records']);
    }

    /**
     * Check login attempt before WordPress processes it
     */
    public function check_login_attempt($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }

        $ip = Utils::get_client_ip();

        // Check blacklist
        if ($this->is_ip_blacklisted($ip)) {
            $this->log("Blocked login attempt from blacklisted IP: $ip", 'warning');
            return new \WP_Error('ip_blocked', 'Your IP address is blocked.');
        }

        // Check whitelist
        if ($this->is_ip_whitelisted($ip)) {
            return $user;
        }

        // Check for too many attempts
        $attempts = $this->get_login_attempts($ip);
        if ($attempts >= $this->max_attempts) {
            $this->log("Blocked login attempt from IP with too many failures: $ip", 'warning');
            return new \WP_Error('too_many_attempts', 'Too many failed login attempts. Please try again later.');
        }

        return $user;
    }

    /**
     * Handle failed login attempt
     */
    public function handle_failed_login($username) {
        $ip = Utils::get_client_ip();
        
        if ($this->is_ip_whitelisted($ip)) {
            return;
        }

        $attempts = $this->get_login_attempts($ip);
        $attempts++;

        $this->log("Failed login attempt from IP: $ip, Username: $username", 'warning');
        
        if ($attempts >= $this->max_attempts) {
            $this->block_ip($ip);
            $this->log("IP blocked due to too many failed attempts: $ip", 'warning');
        } else {
            $this->update_login_attempts($ip, $attempts);
        }
    }

    /**
     * Handle successful login
     */
    public function handle_successful_login($username, $user) {
        $ip = Utils::get_client_ip();
        $this->reset_login_attempts($ip);
        $this->log("Successful login from IP: $ip, Username: $username", 'info');
    }

    /**
     * Check if IP is blacklisted
     */
    private function is_ip_blacklisted($ip) {
        foreach ($this->blacklist as $range) {
            if (Utils::ip_in_range($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if IP is whitelisted
     */
    private function is_ip_whitelisted($ip) {
        foreach ($this->whitelist as $range) {
            if (Utils::ip_in_range($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Block an IP address
     */
    private function block_ip($ip) {
        $this->blacklist[] = $ip;
        update_option($this->options_prefix . 'blacklist', array_unique($this->blacklist));
        $this->update_login_attempts($ip, $this->max_attempts);
    }

    /**
     * Get number of failed login attempts for an IP
     */
    private function get_login_attempts($ip) {
        $attempts = get_transient($this->options_prefix . 'attempts_' . md5($ip));
        return $attempts ? $attempts : 0;
    }

    /**
     * Update failed login attempts for an IP
     */
    private function update_login_attempts($ip, $attempts) {
        set_transient(
            $this->options_prefix . 'attempts_' . md5($ip),
            $attempts,
            $this->block_duration
        );
    }

    /**
     * Reset failed login attempts for an IP
     */
    private function reset_login_attempts($ip) {
        delete_transient($this->options_prefix . 'attempts_' . md5($ip));
    }

    /**
     * Add IP to whitelist
     */
    public function add_to_whitelist($ip) {
        if (!in_array($ip, $this->whitelist)) {
            $this->whitelist[] = $ip;
            update_option($this->options_prefix . 'whitelist', $this->whitelist);
            $this->log("Added IP to whitelist: $ip");
        }
    }

    /**
     * Remove IP from whitelist
     */
    public function remove_from_whitelist($ip) {
        $key = array_search($ip, $this->whitelist);
        if ($key !== false) {
            unset($this->whitelist[$key]);
            update_option($this->options_prefix . 'whitelist', array_values($this->whitelist));
            $this->log("Removed IP from whitelist: $ip");
        }
    }

    /**
     * Add IP to blacklist
     */
    public function add_to_blacklist($ip) {
        if (!in_array($ip, $this->blacklist)) {
            $this->blacklist[] = $ip;
            update_option($this->options_prefix . 'blacklist', $this->blacklist);
            $this->log("Added IP to blacklist: $ip");
        }
    }

    /**
     * Remove IP from blacklist
     */
    public function remove_from_blacklist($ip) {
        $key = array_search($ip, $this->blacklist);
        if ($key !== false) {
            unset($this->blacklist[$key]);
            update_option($this->options_prefix . 'blacklist', array_values($this->blacklist));
            $this->log("Removed IP from blacklist: $ip");
        }
    }

    /**
     * Cleanup old login attempt records
     */
    public function cleanup_old_records() {
        global $wpdb;
        
        $this->log('Starting cleanup of old login attempt records');
        
        // Get all transients related to login attempts
        $prefix = '_transient_' . $this->options_prefix . 'attempts_';
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $wpdb->options WHERE option_name LIKE %s AND option_value >= %d",
            $prefix . '%',
            $this->max_attempts
        ));
        
        $this->log('Completed cleanup of old login attempt records');
    }

    /**
     * Log a message
     */
    private function log($message, $level = 'info') {
        $this->logger->log($message, $level, 'network');
    }
}
