<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Notifications {
	private static $instance = null;
	private $logger;
	private $network;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->logger  = WP_Security_Logger::get_instance();
		$this->network = WP_Security_Site_Network::get_instance();

		add_action( 'wp_security_notification', array( $this, 'process_notification' ), 10, 3 );
		add_action( 'wp_security_daily_report', array( $this, 'send_daily_report' ) );
	}

	public function notify( $type, $message, $data = array() ) {
		$notification = array(
			'type'      => $type,
			'message'   => $message,
			'data'      => $data,
			'site'      => get_site_url(),
			'timestamp' => current_time( 'mysql' ),
		);

		// Log notification
		$this->logger->log( 'notification', $message, $data );

		// Process notification
		do_action( 'wp_security_notification', $type, $message, $data );

		// Share with network if needed
		if ( $this->should_share_notification( $type ) ) {
			$this->network->sync_data( 'notifications' );
		}
	}

	public function send_notification( $type, $message, $data = array() ) {
		return $this->notify( $type, $message, $data );
	}

	private function should_share_notification( $type ) {
		$shared_types = array(
			'malware_detected',
			'brute_force_attack',
			'file_change',
			'critical_update',
			'resource_limit',
		);
		return in_array( $type, $shared_types );
	}

	public function process_notification( $type, $message, $data ) {
		// Email notifications
		if ( $this->should_email( $type ) ) {
			$this->send_email( $type, $message, $data );
		}

		// Admin notices
		if ( $this->should_show_admin( $type ) ) {
			$this->add_admin_notice( $type, $message );
		}

		// Slack/Discord webhooks
		if ( $this->should_webhook( $type ) ) {
			$this->send_webhook( $type, $message, $data );
		}
	}

	private function should_email( $type ) {
		$email_settings = get_option( 'wp_security_email_notifications', array() );
		return isset( $email_settings[ $type ] ) && $email_settings[ $type ];
	}

	private function should_show_admin( $type ) {
		$admin_settings = get_option( 'wp_security_admin_notifications', array() );
		return isset( $admin_settings[ $type ] ) && $admin_settings[ $type ];
	}

	private function should_webhook( $type ) {
		$webhook_settings = get_option( 'wp_security_webhook_notifications', array() );
		return isset( $webhook_settings[ $type ] ) && $webhook_settings[ $type ];
	}

	private function send_email( $type, $message, $data ) {
		$to      = get_option( 'admin_email' );
		$subject = sprintf( '[%s Security] %s Alert', get_bloginfo( 'name' ), ucfirst( $type ) );

		// Get email template
		$template = $this->get_email_template( $type );
		$body     = $this->parse_template(
			$template,
			array(
				'message'   => $message,
				'data'      => $data,
				'site_url'  => get_site_url(),
				'admin_url' => admin_url( 'admin.php?page=wp-security-dashboard' ),
			)
		);

		add_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );
		wp_mail( $to, $subject, $body );
		remove_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );
	}

	public function set_html_content_type() {
		return 'text/html';
	}

	private function get_email_template( $type ) {
		$template_file = plugin_dir_path( __FILE__ ) . '../templates/email-' . $type . '.php';
		if ( file_exists( $template_file ) ) {
			return file_get_contents( $template_file );
		}
		return file_get_contents( plugin_dir_path( __FILE__ ) . '../templates/email-default.php' );
	}

	private function parse_template( $template, $data ) {
		foreach ( $data as $key => $value ) {
			if ( is_array( $value ) ) {
				$value = json_encode( $value, JSON_PRETTY_PRINT );
			}
			$template = str_replace( '{{' . $key . '}}', $value, $template );
		}
		return $template;
	}

	private function add_admin_notice( $type, $message ) {
		add_action(
			'admin_notices',
			function () use ( $type, $message ) {
				$class = 'notice notice-';
				switch ( $type ) {
					case 'critical':
						$class .= 'error';
						break;
					case 'warning':
						$class .= 'warning';
						break;
					default:
						$class .= 'info';
				}
				printf(
					'<div class="%1$s"><p>%2$s</p></div>',
					esc_attr( $class ),
					esc_html( $message )
				);
			}
		);
	}

	private function send_webhook( $type, $message, $data ) {
		$webhooks = get_option( 'wp_security_webhooks', array() );

		if ( empty( $webhooks ) ) {
			return;
		}

		$payload = array(
			'type'      => $type,
			'message'   => $message,
			'data'      => $data,
			'site'      => get_site_url(),
			'timestamp' => current_time( 'mysql' ),
		);

		foreach ( $webhooks as $webhook ) {
			wp_remote_post(
				$webhook['url'],
				array(
					'body'    => json_encode( $payload ),
					'headers' => array( 'Content-Type' => 'application/json' ),
					'timeout' => 5,
				)
			);
		}
	}

	public function send_daily_report() {
		$report_data = $this->generate_report_data();

		if ( empty( $report_data['events'] ) ) {
			return; // No events to report
		}

		$template = $this->get_email_template( 'daily-report' );
		$body     = $this->parse_template( $template, $report_data );

		$to      = get_option( 'admin_email' );
		$subject = sprintf( '[%s Security] Daily Security Report', get_bloginfo( 'name' ) );

		add_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );
		wp_mail( $to, $subject, $body );
		remove_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );
	}

	private function generate_report_data() {
		$yesterday = date( 'Y-m-d', strtotime( '-1 day' ) );

		return array(
			'events'          => $this->logger->get_logs( 'all', 1000 ),
			'stats'           => array(
				'malware_scans'  => get_option( 'wp_security_daily_scans', 0 ),
				'blocked_ips'    => get_option( 'wp_security_blocked_ips', array() ),
				'file_changes'   => get_option( 'wp_security_file_changes', array() ),
				'login_attempts' => get_option( 'wp_security_login_attempts', 0 ),
			),
			'recommendations' => $this->get_security_recommendations(),
			'site_url'        => get_site_url(),
			'admin_url'       => admin_url( 'admin.php?page=wp-security-dashboard' ),
		);
	}

	private function get_security_recommendations() {
		$recommendations = array();

		// Check WordPress core
		if ( get_option( 'wp_security_core_integrity', false ) === false ) {
			$recommendations[] = 'WordPress core files should be verified';
		}

		// Check file permissions
		if ( get_option( 'wp_security_file_permissions', false ) === false ) {
			$recommendations[] = 'Some file permissions need to be adjusted';
		}

		// Check SSL
		if ( ! is_ssl() ) {
			$recommendations[] = 'SSL certificate should be installed';
		}

		return $recommendations;
	}
}
