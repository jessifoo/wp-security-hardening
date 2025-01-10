<?php
namespace WP_Security\Exceptions;

class SecurityException extends \Exception {
	private $context;

	public function __construct( $message, array $context = array() ) {
		parent::__construct( $message );
		$this->context = $context;
	}

	public function getContext(): array {
		return $this->context;
	}
}
