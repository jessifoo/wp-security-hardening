<?php
namespace Tests\Security\Scanner\Base;

class ScanResult {
	private $status;
	private $error;
	private $threats  = array();
	private $warnings = array();
	private $metadata = array();

	public function __construct( string $status ) {
		$this->status = $status;
	}

	public function setError( string $error ): self {
		$this->error = $error;
		return $this;
	}

	public function addThreat( string $type, string $file, array $details ): self {
		$this->threats[] = array(
			'type'    => $type,
			'file'    => $file,
			'details' => $details,
		);
		return $this;
	}

	public function addWarning( string $message, string $file, array $details ): self {
		$this->warnings[] = array(
			'message' => $message,
			'file'    => $file,
			'details' => $details,
		);
		return $this;
	}

	public function addMetadata( string $key, $value ): self {
		$this->metadata[ $key ] = $value;
		return $this;
	}

	public function complete(): self {
		$this->status = 'completed';
		return $this;
	}

	public function hasError(): bool {
		return ! empty( $this->error );
	}

	public function getError(): ?string {
		return $this->error;
	}

	public function getThreats(): array {
		return $this->threats;
	}

	public function getWarnings(): array {
		return $this->warnings;
	}

	public function getMetadata(): array {
		return $this->metadata;
	}

	public function getStatus(): string {
		return $this->status;
	}
}
