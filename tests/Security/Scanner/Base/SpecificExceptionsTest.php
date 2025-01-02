<?php
namespace Tests\Security\Scanner\Base;

use PHPUnit\Framework\TestCase;
use WP_Security\Scanner\Base\{
	ResourceLimitException,
	MalwareDetectedException,
	IntegrityException
};

class SpecificExceptionsTest extends TestCase {
	public function testResourceLimitExceptionFromLimit(): void {
		$exception = ResourceLimitException::fromLimit( 'memory', 256, 128 );

		$this->assertStringContainsString( 'Resource limit exceeded', $exception->getMessage() );
		$this->assertEquals( 'resource_limit', $exception->getContext() );

		$metadata = $exception->getMetadata();
		$this->assertEquals( 'memory', $metadata['resource'] );
		$this->assertEquals( 256, $metadata['current'] );
		$this->assertEquals( 128, $metadata['limit'] );
	}

	public function testMalwareDetectedExceptionFromDetection(): void {
		$file    = '/path/to/infected.php';
		$type    = 'php_malware';
		$details = array( 'signature' => 'evil_pattern' );

		$exception = MalwareDetectedException::fromDetection( $file, $type, $details );

		$this->assertStringContainsString( 'Malware detected', $exception->getMessage() );
		$this->assertEquals( 'malware_detection', $exception->getContext() );

		$metadata = $exception->getMetadata();
		$this->assertEquals( $file, $metadata['file'] );
		$this->assertEquals( $type, $metadata['type'] );
		$this->assertEquals( $details, $metadata['details'] );
	}

	public function testIntegrityExceptionFromCheck(): void {
		$file     = '/path/to/modified.php';
		$expected = 'abc123';
		$actual   = 'def456';

		$exception = IntegrityException::fromCheck( $file, $expected, $actual );

		$this->assertStringContainsString( 'Integrity check failed', $exception->getMessage() );
		$this->assertEquals( 'integrity_check', $exception->getContext() );

		$metadata = $exception->getMetadata();
		$this->assertEquals( $file, $metadata['file'] );
		$this->assertEquals( $expected, $metadata['expected_hash'] );
		$this->assertEquals( $actual, $metadata['actual_hash'] );
	}
}
