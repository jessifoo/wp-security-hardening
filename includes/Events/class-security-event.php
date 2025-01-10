<?php
namespace WP_Security\Events;

class SecurityEvent implements SecurityEventInterface {
	private $type;
	private $severity;
	private $context;

	public function __construct( string $type, string $severity, array $context = array() ) {
		$this->type     = $type;
		$this->severity = $severity;
		$this->context  = $context;
	}

	public function getType(): string {
		return $this->type;
	}

	public function getSeverity(): string {
		return $this->severity;
	}

	public function getContext(): array {
		return $this->context;
	}
}
