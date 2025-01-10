<?php
namespace WP_Security\Events;

use WP_Security\Utils\Logger;

class EventDispatcher {
	private $logger;
	private $listeners = array();

	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	public function addListener( string $event, callable $listener, int $priority = 10 ): void {
		$this->listeners[ $event ][ $priority ][] = $listener;
	}

	public function dispatch( SecurityEventInterface $event ): void {
		$type     = $event->getType();
		$severity = $event->getSeverity();
		$context  = $event->getContext();

		// Log the event
		$this->logger->log( $severity, $type, $context );

		// Notify admin if critical
		if ( $severity === 'critical' ) {
			$this->notifyAdmin( $event );
		}

		// Call listeners
		if ( isset( $this->listeners[ $type ] ) ) {
			ksort( $this->listeners[ $type ] );
			foreach ( $this->listeners[ $type ] as $listeners ) {
				foreach ( $listeners as $listener ) {
					call_user_func( $listener, $event );
				}
			}
		}
	}

	private function notifyAdmin( SecurityEventInterface $event ): void {
		$admin_email = get_option( 'admin_email' );
		$subject     = sprintf( '[Security Alert] %s detected', ucfirst( $event->getType() ) );
		$message     = sprintf(
			"Security Event Details:\n\nType: %s\nSeverity: %s\nContext: %s",
			$event->getType(),
			$event->getSeverity(),
			json_encode( $event->getContext(), JSON_PRETTY_PRINT )
		);

		wp_mail( $admin_email, $subject, $message );
	}
}
