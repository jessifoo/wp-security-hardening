<?php
namespace WP_Security\Security\Scanner\Results;

use WP_Security\Interfaces\CleanupResultInterface;

class CleanupResult implements CleanupResultInterface {
	private $results;

	public function __construct( array $results ) {
		$this->results = $results;
	}

	public function getResults(): array {
		return $this->results;
	}

	public function getSuccessCount(): int {
		return count(
			array_filter(
				$this->results,
				function ( $result ) {
					return $result['success'] ?? false;
				}
			)
		);
	}

	public function getFailureCount(): int {
		return count( $this->results ) - $this->getSuccessCount();
	}
}
