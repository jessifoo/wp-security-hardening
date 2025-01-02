<?php
namespace Tests\Security\Scanner\Base;

use PHPUnit\Framework\TestCase;
use WP_Security\Scanner\Base\{
	ErrorHandlerTrait,
	ScannerException,
	ResourceLimitException,
	MalwareDetectedException,
	IntegrityException,
	ScanResult
};

class ErrorHandlerTraitTest extends TestCase {
	private $handler;
	private $logger;
	private $result;

	protected function setUp(): void {
		// Create mock logger
		$this->logger = $this->createMock( \WP_Security_Logger::class );

		// Create test implementation of trait
		$this->handler = new class() {
			use ErrorHandlerTrait;

			public $logger;
			public $tempFiles = array();
			public $scanStartTime;

			public function cleanup(): void {}

			public function exposedHandleScannerException( $e, $result ): void {
				$this->handleScannerException( $e, $result );
			}

			public function exposedCheckResourceLimits( array $limits ): void {
				$this->checkResourceLimits( $limits );
			}

			public function exposedCreateTempFile( string $prefix ): string {
				return $this->createTempFile( $prefix );
			}
		};

		$this->handler->logger = $this->logger;

		// Create scan result
		$this->result = new ScanResult( 'testing' );
	}

	public function testHandleResourceLimitException(): void {
		$exception = ResourceLimitException::fromLimit( 'memory', 256, 128 );

		$this->logger->expects( $this->once() )
			->method( 'error' )
			->with(
				$this->stringContains( 'Resource limit exceeded' ),
				$this->arrayHasKey( 'context' )
			);

		$this->handler->exposedHandleScannerException( $exception, $this->result );

		$this->assertTrue( $this->result->hasError() );
		$this->assertArrayHasKey( 'resource_limit', $this->result->getMetadata() );
	}

	public function testHandleMalwareDetectedException(): void {
		$exception = MalwareDetectedException::fromDetection(
			'/test.php',
			'malware',
			array( 'details' => 'test' )
		);

		$this->handler->exposedHandleScannerException( $exception, $this->result );

		$threats = $this->result->getThreats();
		$this->assertCount( 1, $threats );
		$this->assertEquals( 'malware', $threats[0]['type'] );
		$this->assertEquals( '/test.php', $threats[0]['file'] );
	}

	public function testHandleIntegrityException(): void {
		$exception = IntegrityException::fromCheck(
			'/test.php',
			'expected',
			'actual'
		);

		$this->handler->exposedHandleScannerException( $exception, $this->result );

		$warnings = $this->result->getWarnings();
		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'Integrity check failed', $warnings[0]['message'] );
	}

	public function testCheckResourceLimits(): void {
		$this->handler->scanStartTime = time() - 10;

		// Should not throw exception
		$this->handler->exposedCheckResourceLimits(
			array(
				'time'   => 20,
				'memory' => PHP_INT_MAX,
			)
		);

		// Should throw exception
		$this->expectException( ResourceLimitException::class );
		$this->handler->exposedCheckResourceLimits(
			array(
				'time' => 5, // Less than elapsed time
			)
		);
	}

	public function testCreateTempFile(): void {
		$tempFile = $this->handler->exposedCreateTempFile( 'test_' );

		$this->assertFileExists( $tempFile );
		$this->assertContains( $tempFile, $this->handler->tempFiles );

		// Cleanup
		unlink( $tempFile );
	}

	protected function tearDown(): void {
		// Cleanup any remaining temp files
		foreach ( $this->handler->tempFiles as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
	}
}
