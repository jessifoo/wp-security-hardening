<?php
/**
 * Test case for the WP_Security_Utils class.
 *
 * @package WP_Security_Hardening
 * @subpackage Tests
 */

/**
 * Class WP_Security_Utils_Test
 */
class WP_Security_Utils_Test extends WP_Mock\Tools\TestCase {
	/**
	 * The utils instance being tested.
	 *
	 * @var WP_Security_Utils
	 */
	private $utils;

	/**
	 * Set up the test environment.
	 */
	public function setUp(): void {
		parent::setUp();
		WP_Mock::setUp();
		$this->utils = new WP_Security_Utils();
	}

	/**
	 * Tear down the test environment.
	 */
	public function tearDown(): void {
		WP_Mock::tearDown();
		parent::tearDown();
	}

	/**
	 * Test successful API request.
	 */
	public function test_wp_api_request_success() {
		$url               = 'https://api.wordpress.org/test';
		$expected_response = array( 'version' => '1.0' );

		WP_Mock::userFunction( 'wp_remote_get' )
			->once()
			->with( $url, array() )
			->andReturn( array( 'body' => wp_json_encode( $expected_response ) ) );

		WP_Mock::userFunction( 'wp_remote_retrieve_body' )
			->once()
			->andReturn( wp_json_encode( $expected_response ) );

		$result = $this->utils->wp_api_request( $url );
		$this->assertEquals( $expected_response, $result );
	}

	/**
	 * Test failed API request.
	 */
	public function test_wp_api_request_failure() {
		$url   = 'https://api.wordpress.org/test';
		$error = new WP_Error( 'test_error', 'Test error message' );

		WP_Mock::userFunction( 'wp_remote_get' )
			->once()
			->with( $url, array() )
			->andReturn( $error );

		$result = $this->utils->wp_api_request( $url );
		$this->assertInstanceOf( 'WP_Error', $result );
	}

	/**
	 * Test getting file hash.
	 */
	public function test_get_file_hash() {
		$file          = '/test/file.txt';
		$expected_hash = 'abc123';

		WP_Mock::userFunction( 'file_exists' )
			->once()
			->with( $file )
			->andReturn( true );

		WP_Mock::userFunction( 'md5_file' )
			->once()
			->with( $file )
			->andReturn( $expected_hash );

		$result = $this->utils->get_file_hash( $file );
		$this->assertEquals( $expected_hash, $result );
	}

	/**
	 * Test getting core files.
	 */
	public function test_get_core_files() {
		$directory = '/wp-root';
		$files     = array(
			'/wp-root/wp-admin/file1.php',
			'/wp-root/wp-includes/file2.php',
			'/wp-root/wp-content/file3.php',
		);

		$dir      = $this->createMock( 'RecursiveDirectoryIterator' );
		$iterator = $this->createMock( 'RecursiveIteratorIterator' );

		$file_objects = array();
		foreach ( $files as $file ) {
			$file_object = $this->createMock( 'SplFileInfo' );
			$file_object->method( 'isFile' )->willReturn( true );
			$file_object->method( 'getPathname' )->willReturn( $file );
			$file_objects[] = $file_object;
		}

		$iterator->method( 'rewind' )->willReturn( true );
		$iterator->method( 'valid' )->will( $this->onConsecutiveCalls( true, true, true, false ) );
		$iterator->method( 'current' )->will( $this->onConsecutiveCalls( ...$file_objects ) );
		$iterator->method( 'next' )->willReturn( null );

		$result = $this->utils->get_core_files( $directory );
		$this->assertCount( 2, $result );
		$this->assertContains( '/wp-root/wp-admin/file1.php', $result );
		$this->assertContains( '/wp-root/wp-includes/file2.php', $result );
	}

	/**
	 * Test checking if a file is a core file.
	 */
	public function test_is_core_file() {
		$core_file     = '/wp-root/wp-admin/file.php';
		$non_core_file = '/wp-root/wp-content/file.php';

		$this->assertTrue( $this->utils->is_core_file( $core_file ) );
		$this->assertFalse( $this->utils->is_core_file( $non_core_file ) );
	}

	/**
	 * Test backing up a file.
	 */
	public function test_backup_file() {
		$file = '/test/file.txt';

		WP_Mock::userFunction( 'file_exists' )
			->once()
			->with( $file )
			->andReturn( true );

		WP_Mock::userFunction( 'copy' )
			->once()
			->andReturn( true );

		$result = $this->utils->backup_file( $file );
		$this->assertTrue( $result );
	}

	/**
	 * Test downloading a file.
	 */
	public function test_download_file() {
		$url         = 'https://example.com/file.txt';
		$destination = '/test/file.txt';
		$content     = 'file content';

		WP_Mock::userFunction( 'wp_remote_get' )
			->once()
			->with( $url )
			->andReturn( array( 'body' => $content ) );

		WP_Mock::userFunction( 'wp_remote_retrieve_body' )
			->once()
			->andReturn( $content );

		WP_Mock::userFunction( 'file_put_contents' )
			->once()
			->with( $destination, $content )
			->andReturn( strlen( $content ) );

		$result = $this->utils->download_file( $url, $destination );
		$this->assertTrue( $result );
	}

	/**
	 * Test getting WordPress locale.
	 */
	public function test_get_wp_locale() {
		WP_Mock::userFunction( 'get_locale' )
			->once()
			->andReturn( 'en_US' );

		$result = $this->utils->get_wp_locale();
		$this->assertEquals( 'en_US', $result );
	}

	/**
	 * Test getting WordPress version.
	 */
	public function test_get_wp_version() {
		$expected_version = '5.8';
		WP_Mock::userFunction( 'get_bloginfo' )
			->once()
			->with( 'version' )
			->andReturn( $expected_version );

		$result = $this->utils->get_wp_version();
		$this->assertEquals( $expected_version, $result );
	}

	/**
	 * Test checking file permissions.
	 */
	public function test_has_secure_permissions() {
		$file = '/test/file.txt';

		WP_Mock::userFunction( 'file_exists' )
			->once()
			->with( $file )
			->andReturn( true );

		WP_Mock::userFunction( 'fileperms' )
			->once()
			->with( $file )
			->andReturn( 0644 );

		WP_Mock::userFunction( 'is_dir' )
			->once()
			->with( $file )
			->andReturn( false );

		$result = $this->utils->has_secure_permissions( $file );
		$this->assertTrue( $result );
	}

	/**
	 * Test sanitizing a path.
	 */
	public function test_sanitize_path() {
		$path     = '\\test\\path\\\\';
		$expected = '/test/path';

		$result = $this->utils->sanitize_path( $path );
		$this->assertEquals( $expected, $result );
	}

	/**
	 * Test checking if running on Windows.
	 */
	public function test_is_windows() {
		$result = $this->utils->is_windows();
		$this->assertIsBool( $result );
	}

	/**
	 * Test getting temporary directory.
	 */
	public function test_get_temp_dir() {
		WP_Mock::userFunction( 'sys_get_temp_dir' )
			->once()
			->andReturn( '/tmp' );

		$result = $this->utils->get_temp_dir();
		$this->assertEquals( '/tmp', $result );
	}

	/**
	 * Test creating temporary filename.
	 */
	public function test_create_temp_filename() {
		$prefix   = 'test_';
		$temp_dir = '/tmp';
		$expected = '/tmp/test_abc123';

		WP_Mock::userFunction( 'sys_get_temp_dir' )
			->once()
			->andReturn( $temp_dir );

		WP_Mock::userFunction( 'tempnam' )
			->once()
			->with( $temp_dir, $prefix )
			->andReturn( $expected );

		$result = $this->utils->create_temp_filename( $prefix );
		$this->assertEquals( $expected, $result );
	}
}
