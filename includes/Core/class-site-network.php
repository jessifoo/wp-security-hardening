<?php
/**
 * WP Security Site Network Class
 *
 * Handles network-wide operations and settings synchronization for WordPress multisite.
 *
 * @package WP_Security
 * @subpackage Core
 */

class WP_Security_Site_Network {
    /**
     * Network sites
     *
     * @var array
     */
    private $sites = array();

    /**
     * Constructor
     */
    public function __construct() {
        if (is_multisite()) {
            $this->sites = get_sites();
        }
    }

    /**
     * Check if plugin is network active
     *
     * @return bool
     */
    public function is_network_active() {
        if (!function_exists('is_plugin_active_for_network')) {
            require_once(ABSPATH . '/wp-admin/includes/plugin.php');
        }
        return is_plugin_active_for_network('wp-security-hardening/wp-security-hardening.php');
    }

    /**
     * Get all network sites
     *
     * @return array List of site objects
     */
    public function get_sites() {
        return $this->sites;
    }

    /**
     * Sync settings across all network sites
     *
     * @param array $settings Settings to sync
     * @return bool Success status
     */
    public function sync_settings($settings) {
        if (!$this->is_network_active()) {
            return false;
        }

        foreach ($this->sites as $site) {
            switch_to_blog($site->blog_id);
            
            foreach ($settings as $option => $value) {
                update_option($option, $value);
            }
            
            restore_current_blog();
        }

        return true;
    }

    /**
     * Get settings from a specific site
     *
     * @param int $site_id Site ID
     * @param array $options Options to retrieve
     * @return array Site settings
     */
    public function get_site_settings($site_id, $options) {
        $settings = array();
        
        switch_to_blog($site_id);
        
        foreach ($options as $option) {
            $settings[$option] = get_option($option);
        }
        
        restore_current_blog();
        
        return $settings;
    }
}
