<?php
namespace WP_Security\Security\Scanner\Results;

use WP_Security\Interfaces\ScanResultInterface;

class ScanResult implements ScanResultInterface {
	private $threats  = array();
	private $stats    = array();
	private $metadata = array();

	public function addThreat( string $type, string $file, array $context = array() ): void {
		$this->threats[] = array(
			'type'      => $type,
			'file'      => $file,
			'context'   => $context,
			'timestamp' => current_time( 'mysql' ),
		);
	}

	public function addStat( string $key, $value ): void {
		$this->stats[ $key ] = $value;
	}

	public function addMetadata( string $key, $value ): void {
		$this->metadata[ $key ] = $value;
	}

	public function getResults(): array {
		return array(
			'threats'  => $this->threats,
			'stats'    => $this->stats,
			'metadata' => $this->metadata,
		);
	}

	public function hasThreats(): bool {
		return ! empty( $this->threats );
	}

	public function getThreatCount(): int {
		return count( $this->threats );
	}

	public function getThreats(): array {
		return $this->threats;
	}
}
