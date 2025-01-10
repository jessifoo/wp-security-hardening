<?php
namespace WP_Security\Interfaces;

interface CleanupResultInterface {
	public function getResults(): array;
	public function getSuccessCount(): int;
	public function getFailureCount(): int;
}
