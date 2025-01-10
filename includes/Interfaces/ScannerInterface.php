<?php
namespace WP_Security\Interfaces;

interface ScannerInterface {
	public function scan( array $options = array() ): ScanResultInterface;
	public function cleanup( array $threats ): CleanupResultInterface;
}
