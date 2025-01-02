<?php

use PHPUnit\Framework\TestCase;

class WP_Security_Quarantine_Manager_Test extends TestCase {
	private $quarantine_manager;

	public function setUp(): void {
		parent::setUp();
		$this->quarantine_manager = new WP_Security_Quarantine_Manager();
	}

	public function test_quarantine_file() {
		$test_file = __DIR__ . '/test-data/malicious.php';
		file_put_contents( $test_file, '<?php system($_GET["cmd"]); ?>' );

		$threat_details = array(
			'type'        => 'malicious_function',
			'severity'    => 'high',
			'description' => 'Dangerous system function detected',
		);

		$result = $this->quarantine_manager->quarantine_file( $test_file, $threat_details );
		$this->assertTrue( $result );

		// Check if original file is removed
		$this->assertFalse( file_exists( $test_file ) );

		// Check quarantine log
		$quarantine_list = $this->quarantine_manager->get_quarantine_list();
		$this->assertNotEmpty( $quarantine_list );

		$latest_quarantine = end( $quarantine_list );
		$this->assertEquals( $test_file, $latest_quarantine['original_path'] );
	}

	public function test_restore_file() {
		// First quarantine a file
		$test_file        = __DIR__ . '/test-data/test-restore.php';
		$original_content = '<?php echo "Test content"; ?>';
		file_put_contents( $test_file, $original_content );

		$this->quarantine_manager->quarantine_file( $test_file, array( 'type' => 'test' ) );

		// Get quarantine name
		$quarantine_list   = $this->quarantine_manager->get_quarantine_list();
		$latest_quarantine = end( $quarantine_list );

		// Restore file
		$result = $this->quarantine_manager->restore_file( $latest_quarantine['quarantine_name'] );
		$this->assertTrue( $result );

		// Check if file is restored with correct content
		$this->assertTrue( file_exists( $test_file ) );
		$this->assertEquals( $original_content, file_get_contents( $test_file ) );

		unlink( $test_file );
	}

	public function test_quarantine_cleanup() {
		// Create some test files
		$files = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$test_file = __DIR__ . "/test-data/test{$i}.php";
			file_put_contents( $test_file, "<?php echo {$i}; ?>" );
			$files[] = $test_file;
			$this->quarantine_manager->quarantine_file( $test_file, array( 'type' => 'test' ) );
		}

		// Run cleanup
		$this->quarantine_manager->cleanup_quarantine();

		// Check quarantine stats
		$stats = $this->quarantine_manager->get_quarantine_stats();
		$this->assertLessThanOrEqual( $stats['max_size'], $stats['total_size'] );

		// Cleanup test files
		foreach ( $files as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
	}
}
