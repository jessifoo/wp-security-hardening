<?php

namespace WP_Security\Tests\Core;

use PHPUnit\Framework\TestCase;
use WP_Security\Core\Core_Manager;
use WP_Security\Utils\Utils;
use WP_Mock;

class CoreManagerTest extends TestCase {
	private $core_manager;
	private $utils;

	public function setUp(): void {
		parent::setUp();
		WP_Mock::setUp();

		$this->utils        = $this->createMock( Utils::class );
		$this->core_manager = new Core_Manager( $this->utils );
	}

	public function tearDown(): void {
		WP_Mock::tearDown();
		parent::tearDown();
	}

	public function test_get_core_checksums_success() {
		// Mock WordPress version
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		// Mock WordPress.org API response
		$expected_checksums = array(
			'wp-admin/index.php'      => 'abcd1234',
			'wp-includes/version.php' => 'efgh5678',
		);

		$api_response = array(
			'body' => json_encode(
				array(
					'checksums' => $expected_checksums,
				)
			),
		);

		// Mock wp_remote_get
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => $api_response,
			)
		);

		// Mock wp_remote_retrieve_response_code
		WP_Mock::userFunction(
			'wp_remote_retrieve_response_code',
			array(
				'times'  => 1,
				'return' => 200,
			)
		);

		// Mock wp_remote_retrieve_body
		WP_Mock::userFunction(
			'wp_remote_retrieve_body',
			array(
				'times'  => 1,
				'return' => json_encode( array( 'checksums' => $expected_checksums ) ),
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertIsArray( $result );
		$this->assertEquals( $expected_checksums, $result );
	}

	public function test_get_core_checksums_api_error() {
		// Mock WordPress version
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		// Mock wp_remote_get to return WP_Error
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => new \WP_Error( 'http_request_failed', 'API request failed' ),
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertFalse( $result );
	}

	public function test_get_core_checksums_invalid_response() {
		// Mock WordPress version
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		// Mock wp_remote_get
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => array( 'body' => 'invalid json' ),
			)
		);

		// Mock wp_remote_retrieve_response_code
		WP_Mock::userFunction(
			'wp_remote_retrieve_response_code',
			array(
				'times'  => 1,
				'return' => 200,
			)
		);

		// Mock wp_remote_retrieve_body
		WP_Mock::userFunction(
			'wp_remote_retrieve_body',
			array(
				'times'  => 1,
				'return' => 'invalid json',
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertFalse( $result );
	}

	public function test_get_core_checksums_missing_checksums() {
		// Mock WordPress version
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		// Mock wp_remote_get
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => array( 'body' => json_encode( array( 'no_checksums' => array() ) ) ),
			)
		);

		// Mock wp_remote_retrieve_response_code
		WP_Mock::userFunction(
			'wp_remote_retrieve_response_code',
			array(
				'times'  => 1,
				'return' => 200,
			)
		);

		// Mock wp_remote_retrieve_body
		WP_Mock::userFunction(
			'wp_remote_retrieve_body',
			array(
				'times'  => 1,
				'return' => json_encode( array( 'no_checksums' => array() ) ),
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertFalse( $result );
	}

	public function test_get_core_checksums_non_200_response() {
		// Mock WordPress version
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		// Mock wp_remote_get
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => array( 'body' => '' ),
			)
		);

		// Mock wp_remote_retrieve_response_code
		WP_Mock::userFunction(
			'wp_remote_retrieve_response_code',
			array(
				'times'  => 1,
				'return' => 404,
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertFalse( $result );
	}

	public function test_get_core_checksums_locale_filter() {
		// Mock WordPress version and locale
		WP_Mock::userFunction(
			'get_bloginfo',
			array(
				'args'   => array( 'version' ),
				'times'  => 1,
				'return' => '6.4.2',
			)
		);

		WP_Mock::userFunction(
			'get_locale',
			array(
				'times'  => 1,
				'return' => 'fr_FR',
			)
		);

		$expected_checksums = array(
			'wp-admin/index.php'      => 'abcd1234_fr',
			'wp-includes/version.php' => 'efgh5678_fr',
		);

		// Mock wp_remote_get
		WP_Mock::userFunction(
			'wp_remote_get',
			array(
				'times'  => 1,
				'return' => array( 'body' => json_encode( array( 'checksums' => $expected_checksums ) ) ),
			)
		);

		// Mock wp_remote_retrieve_response_code
		WP_Mock::userFunction(
			'wp_remote_retrieve_response_code',
			array(
				'times'  => 1,
				'return' => 200,
			)
		);

		// Mock wp_remote_retrieve_body
		WP_Mock::userFunction(
			'wp_remote_retrieve_body',
			array(
				'times'  => 1,
				'return' => json_encode( array( 'checksums' => $expected_checksums ) ),
			)
		);

		$result = $this->core_manager->get_core_checksums();

		$this->assertIsArray( $result );
		$this->assertEquals( $expected_checksums, $result );
	}
}
