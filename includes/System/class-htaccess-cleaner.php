<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Htaccess_Cleaner {
	private $htaccess_path;
	private $backup_path;
	private $malicious_patterns = array(
		// Malicious redirects
		'/RewriteRule.*(?:eval|base64_decode|system|shell_exec).*$/im',
		'/RewriteCond.*%\{HTTP_REFERER\}.*$/im',
		'/Redirect.*\s+(?:30[1237]|50[012345])\s+https?:\/\/[^\s]+$/im',

		// PHP execution in uploads
		'/SetHandler\s+application\/x-httpd-php/im',
		'/AddType\s+application\/x-httpd-php/im',

		// Bad bot rules that might block legitimate crawlers
		'/RewriteCond.*HTTP_USER_AGENT.*(?:bot|crawler|spider).*$/im',

		// Suspicious environment variable checks
		'/SetEnvIf.*(?:base64_encode|eval|system).*$/im',

		// Malicious file access
		'/RewriteRule.*\.(php|phtml|php3|php4|php5|php7).*$/im',

		// SEO spam redirects
		'/RewriteRule.*\s+https?:\/\/[^\s]+(?:viagra|cialis|poker|casino).*$/im',
	);

	private $safe_rules = array(
		// Block PHP execution in uploads
		'<Directory "' . ABSPATH . 'wp-content/uploads">
    <FilesMatch "\.(?:php|phtml|php3|php4|php5|php7|phps|phar)$">
        Order Deny,Allow
        Deny from all
    </FilesMatch>
</Directory>',

		// Protect wp-config.php
		'<Files wp-config.php>
    Order Deny,Allow
    Deny from all
</Files>',

		// Block access to readme.html, license.txt etc
		'<FilesMatch "^(?:readme|license|changelog|debug)\.(txt|html|log)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>',

		// Prevent directory listing
		'Options -Indexes',

		// Basic security headers
		'Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"',
	);

	public function __construct() {
		$this->htaccess_path = ABSPATH . '.htaccess';
		$this->backup_path   = ABSPATH . '.htaccess.backup';

		// Check and clean .htaccess every hour
		add_action( 'wp_security_htaccess_check', array( $this, 'auto_clean_htaccess' ) );
		if ( ! wp_next_scheduled( 'wp_security_htaccess_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'wp_security_htaccess_check' );
		}
	}

	public function auto_clean_htaccess() {
		// Skip if no .htaccess exists
		if ( ! file_exists( $this->htaccess_path ) ) {
			return;
		}

		// Backup current .htaccess
		copy( $this->htaccess_path, $this->backup_path );

		// Get current content
		$content          = file_get_contents( $this->htaccess_path );
		$original_content = $content;

		// Remove malicious rules
		foreach ( $this->malicious_patterns as $pattern ) {
			$content = preg_replace( $pattern, '', $content );
		}

		// Get WordPress rules
		$wp_rules = '';
		if ( function_exists( 'get_home_path' ) ) {
			$wp_rules = extract_from_markers( $this->htaccess_path, 'WordPress' );
			$wp_rules = implode( "\n", $wp_rules );
		}

		// Build new .htaccess
		$new_content = "# BEGIN WordPress Security\n";
		foreach ( $this->safe_rules as $rule ) {
			$new_content .= $rule . "\n\n";
		}
		$new_content .= "# END WordPress Security\n\n";

		// Add WordPress rules if they exist
		if ( ! empty( $wp_rules ) ) {
			$new_content .= "# BEGIN WordPress\n";
			$new_content .= $wp_rules . "\n";
			$new_content .= "# END WordPress\n\n";
		}

		// Add cleaned custom rules
		$custom_rules = preg_replace( '/# BEGIN WordPress.*# END WordPress\s*/s', '', $content );
		$new_content .= trim( $custom_rules );

		// Only update if content changed
		if ( $new_content !== $original_content ) {
			file_put_contents( $this->htaccess_path, $new_content );

			// Verify the new .htaccess works
			if ( ! $this->verify_htaccess() ) {
				// Restore backup if new one breaks the site
				copy( $this->backup_path, $this->htaccess_path );
			}
		}
	}

	private function verify_htaccess() {
		// Try to access the site
		$response = wp_remote_get( home_url() );

		// If we can't access the site, the .htaccess might be broken
		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return false;
		}

		return true;
	}

	public function get_recommended_rules() {
		return $this->safe_rules;
	}

	private function get_security_rules() {
		return array(
			'# Disable directory browsing'               =>
			'Options -Indexes',

			'# Protect wp-config.php'                    =>
			'<Files wp-config.php>
				Order allow,deny
				Deny from all
			</Files>',

			'# Protect .htaccess'                        =>
			'<Files .htaccess>
				Order allow,deny
				Deny from all
			</Files>',

			'# Block PHP execution in uploads'           =>
			'<Directory wp-content/uploads>
				<FilesMatch ".+\.(?i:php|phtml|php3|php4|php5|php7|pht|phar|phps)$">
					Order allow,deny
					Deny from all
				</FilesMatch>
			</Directory>',

			'# Block suspicious query strings'           =>
			'RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
			RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
			RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
			RewriteRule .* - [F,L]',

			'# Prevent direct access to sensitive files' =>
			'<FilesMatch "^(wp-config\.php|php\.ini|php5\.ini|install\.php|readme\.html|readme\.txt|bb-config\.php|\.htaccess|\.htpasswd|error_log|error\.log)$">
				Order allow,deny
				Deny from all
			</FilesMatch>',

			'# Block access to sensitive directories'    =>
			'RedirectMatch 403 ^/(?:wp-admin|wp-includes|wp-content/plugins|wp-content/themes)/.*\.php$',

			'# Limit file upload types'                  =>
			'AddHandler cgi-script .php .php3 .php4 .phtml .pl .py .jsp .asp .htm .shtml .sh .cgi
			ForceType application/x-httpd-php
			<FilesMatch ".+\.(?i:php|phtml|php3|php4|php5|php7|pht|phar|phps)$">
				SetHandler application/x-httpd-php
			</FilesMatch>',

			'# Prevent script injection'                 =>
			'RewriteCond %{REQUEST_METHOD} ^(HEAD|TRACE|DELETE|TRACK|DEBUG) [NC]
			RewriteRule .* - [F,L]',

			'# Block WordPress xmlrpc.php requests'      =>
			'<Files xmlrpc.php>
				Order Deny,Allow
				Deny from all
			</Files>',

			'# Custom error pages'                       =>
			'ErrorDocument 400 /error.php
			ErrorDocument 403 /error.php
			ErrorDocument 404 /error.php
			ErrorDocument 500 /error.php',
		);
	}

	public function harden_htaccess() {
		$htaccess_path = ABSPATH . '.htaccess';
		$backup_path   = ABSPATH . '.htaccess.backup.' . time();

		// Backup existing .htaccess
		if ( file_exists( $htaccess_path ) ) {
			copy( $htaccess_path, $backup_path );
		}

		// Get WordPress rules
		$wp_rules = '';
		if ( function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			$wp_rules = extract_from_markers( $htaccess_path, 'WordPress' );
		}

		// Combine rules
		$rules = array_merge(
			array( '# BEGIN WordPress Security Hardening' ),
			$this->get_security_rules(),
			array( '# END WordPress Security Hardening' ),
			array( '# BEGIN WordPress' ),
			$wp_rules,
			array( '# END WordPress' )
		);

		// Write new .htaccess
		file_put_contents( $htaccess_path, implode( "\n", $rules ) );
		$this->logger->log( 'Hardened .htaccess file with security rules' );
	}
}
