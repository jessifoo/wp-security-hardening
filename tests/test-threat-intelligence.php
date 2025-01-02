<?php

use PHPUnit\Framework\TestCase;

class WP_Security_Threat_Intelligence_Test extends TestCase {
	private $threat_intelligence;

	public function setUp(): void {
		parent::setUp();
		$this->threat_intelligence = new WP_Security_Threat_Intelligence();
	}

	public function test_analyze_code_content() {
		$safe_code = '<?php echo "Hello World"; ?>';
		$result    = $this->threat_intelligence->analyze_code_content( $safe_code );
		$this->assertFalse( $result['is_malicious'] );

		$malicious_code = '<?php eval(base64_decode($_POST["x"])); ?>';
		$result         = $this->threat_intelligence->analyze_code_content( $malicious_code );
		$this->assertTrue( $result['is_malicious'] );
	}

	public function test_pattern_extraction() {
		$code = '<?php 
            $x = $_POST["input"];
            eval($x);
            system($_GET["cmd"]);
        ?>';

		$patterns = $this->threat_intelligence->extract_patterns_from_code( $code );
		$this->assertContains( 'eval', $patterns['dangerous_functions'] );
		$this->assertContains( 'system', $patterns['dangerous_functions'] );
	}

	public function test_obfuscation_detection() {
		$obfuscated_code = '<?php $x="ZXZhbCgkX1BPU1RbJ3gnXSk="; eval(base64_decode($x)); ?>';
		$result          = $this->threat_intelligence->analyze_code_content( $obfuscated_code );
		$this->assertTrue( $result['is_obfuscated'] );

		$clean_code = '<?php echo "Hello World"; ?>';
		$result     = $this->threat_intelligence->analyze_code_content( $clean_code );
		$this->assertFalse( $result['is_obfuscated'] );
	}

	public function test_api_rate_limiting() {
		$site       = 'jessica-johnson.ca';
		$calls_made = 0;

		// Test API call tracking
		for ( $i = 0; $i < 10; $i++ ) {
			if ( $this->threat_intelligence->can_make_api_call( $site ) ) {
				++$calls_made;
				$this->threat_intelligence->track_api_call( $site );
			}
		}

		$daily_limit = 500 / 3; // Shared limit across 3 sites
		$this->assertLessThanOrEqual( $daily_limit, $calls_made );
	}
}
