<?php

use PHPUnit\Framework\TestCase;

class WP_Security_File_Integrity_Test extends TestCase {
	private $file_integrity;

	public function setUp(): void {
		parent::setUp();
		$this->file_integrity = new WP_Security_File_Integrity();
	}

	public function test_check_core_files() {
		$result = $this->file_integrity->check_core_files();
		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'status', $result );
		$this->assertArrayHasKey( 'modified_files', $result );
	}

	public function test_verify_plugin_files() {
		$test_plugin = 'wp-security-hardening/wp-security-hardening.php';
		$result      = $this->file_integrity->verify_plugin_files( $test_plugin );
		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'status', $result );
	}

	public function test_malware_scan() {
		$test_file = __DIR__ . '/test-data/clean-file.php';
		file_put_contents( $test_file, '<?php echo "Hello World"; ?>' );

		$result = $this->file_integrity->check_file_integrity( $test_file );
		$this->assertFalse( $result['malware_detected'] );

		unlink( $test_file );
	}

	public function test_quarantine_integration() {
		$test_file = __DIR__ . '/test-data/suspicious-file.php';
		file_put_contents( $test_file, '<?php eval($_POST["cmd"]); ?>' );

		$result = $this->file_integrity->check_file_integrity( $test_file );
		$this->assertTrue( $result['malware_detected'] );
		$this->assertTrue( $result['quarantined'] );

		unlink( $test_file );
	}
}
