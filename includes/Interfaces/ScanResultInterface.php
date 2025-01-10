<?php
namespace WP_Security\Interfaces;

interface ScanResultInterface {
	public function getResults(): array;
	public function hasThreats(): bool;
	public function getThreatCount(): int;
}
