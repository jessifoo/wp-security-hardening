<?php
namespace WP_Security\Events;

interface SecurityEventInterface {
	public function getType(): string;
	public function getSeverity(): string;
	public function getContext(): array;
}
