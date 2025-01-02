<?php
namespace Tests\Security\Scanner\Base;

use PHPUnit\Framework\TestCase;
use WP_Security\Scanner\Base\ScannerException;

class ScannerExceptionTest extends TestCase {
	public function testConstructorSetsAllProperties(): void {
		$message  = 'Test error message';
		$context  = 'test_context';
		$metadata = array( 'key' => 'value' );
		$code     = 123;
		$previous = new \Exception( 'Previous error' );

		$exception = new ScannerException(
			$message,
			$context,
			$metadata,
			$code,
			$previous
		);

		$this->assertEquals( $message, $exception->getMessage() );
		$this->assertEquals( $context, $exception->getContext() );
		$this->assertEquals( $metadata, $exception->getMetadata() );
		$this->assertEquals( $code, $exception->getCode() );
		$this->assertSame( $previous, $exception->getPrevious() );
	}

	public function testToArrayIncludesAllInformation(): void {
		$exception = new ScannerException(
			'Test message',
			'test_context',
			array( 'key' => 'value' ),
			123
		);

		$array = $exception->toArray();

		$this->assertArrayHasKey( 'message', $array );
		$this->assertArrayHasKey( 'code', $array );
		$this->assertArrayHasKey( 'context', $array );
		$this->assertArrayHasKey( 'metadata', $array );
		$this->assertArrayHasKey( 'file', $array );
		$this->assertArrayHasKey( 'line', $array );
		$this->assertArrayHasKey( 'trace', $array );

		$this->assertEquals( 'Test message', $array['message'] );
		$this->assertEquals( 123, $array['code'] );
		$this->assertEquals( 'test_context', $array['context'] );
		$this->assertEquals( array( 'key' => 'value' ), $array['metadata'] );
	}

	public function testExceptionInheritance(): void {
		$exception = new ScannerException( 'Test' );
		$this->assertInstanceOf( \Exception::class, $exception );
	}
}
