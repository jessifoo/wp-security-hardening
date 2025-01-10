<?php

namespace WP_Security\Core\Logger;

/**
 * PSR-3 compliant logger interface
 */
interface LoggerInterface {
	/**
	 * System is unusable.
	 */
	public function emergency( string $message, array $context = array() ): void;

	/**
	 * Action must be taken immediately.
	 */
	public function alert( string $message, array $context = array() ): void;

	/**
	 * Critical conditions.
	 */
	public function critical( string $message, array $context = array() ): void;

	/**
	 * Runtime errors that do not require immediate action.
	 */
	public function error( string $message, array $context = array() ): void;

	/**
	 * Exceptional occurrences that are not errors.
	 */
	public function warning( string $message, array $context = array() ): void;

	/**
	 * Normal but significant events.
	 */
	public function notice( string $message, array $context = array() ): void;

	/**
	 * Interesting events.
	 */
	public function info( string $message, array $context = array() ): void;

	/**
	 * Detailed debug information.
	 */
	public function debug( string $message, array $context = array() ): void;

	/**
	 * Logs with an arbitrary level.
	 */
	public function log( string $level, string $message, array $context = array() ): void;
}
