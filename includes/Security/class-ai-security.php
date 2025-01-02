<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Analysis {
	private $threat_intel;
	private $threat_apis;
	private $api_manager;
	private $logger;
	private $last_analysis;

	public function __construct() {
		require_once __DIR__ . '/class-threat-intelligence.php';
		require_once __DIR__ . '/class-threat-apis.php';
		require_once __DIR__ . '/class-wp-security-api-manager.php';
		require_once __DIR__ . '/class-logger.php';

		$this->threat_intel = new WP_Security_Threat_Intelligence();
		$this->threat_apis  = new WP_Security_Threat_APIs();
		$this->api_manager  = new WP_Security_API_Manager();
		$this->logger       = new WP_Security_Logger();
	}

	/**
	 * Analyze security threats using multiple free APIs
	 */
	public function analyze_threats( $data ) {
		WP_Security_Performance_Profiler::start_timing( 'security_analysis' );

		try {
			$results = array();

			// Check WordPress vulnerabilities
			if ( $this->api_manager->can_call( 'wpvulndb', 'daily' ) ) {
				$results['vulnerabilities'] = $this->threat_intel->check_vulnerabilities();
			}

			// Check suspicious IPs
			if ( $this->api_manager->can_call( 'abuseipdb', 'daily' ) ) {
				$results['ip_threats'] = $this->threat_apis->check_ip_batch( $data['ips'] );
			}

			// Check suspicious URLs
			if ( $this->api_manager->can_call( 'urlscan', 'daily' ) ) {
				$results['url_threats'] = $this->threat_apis->check_urls( $data['urls'] );
			}

			// Check for phishing
			if ( $this->api_manager->can_call( 'phishtank', 'daily' ) ) {
				$results['phishing'] = $this->threat_apis->check_phishing( $data['urls'] );
			}

			// Get GitHub security advisories
			$results['advisories'] = $this->threat_intel->get_security_advisories();

			$this->last_analysis = $results;
			return $this->generate_analysis_report( $results );

		} finally {
			WP_Security_Performance_Profiler::end_timing( 'security_analysis' );
		}
	}

	/**
	 * Generate security recommendations based on analysis
	 */
	public function generate_recommendations() {
		WP_Security_Performance_Profiler::start_timing( 'generate_recommendations' );

		try {
			if ( empty( $this->last_analysis ) ) {
				return array( 'error' => 'No analysis data available' );
			}

			$recommendations = array();

			// Process vulnerability findings
			if ( ! empty( $this->last_analysis['vulnerabilities'] ) ) {
				foreach ( $this->last_analysis['vulnerabilities'] as $vuln ) {
					$recommendations[] = array(
						'type'      => 'vulnerability',
						'severity'  => $vuln['severity'],
						'component' => $vuln['component'],
						'action'    => $vuln['recommendation'],
					);
				}
			}

			// Process IP threats
			if ( ! empty( $this->last_analysis['ip_threats'] ) ) {
				foreach ( $this->last_analysis['ip_threats'] as $ip => $threat ) {
					if ( $threat['score'] > 50 ) {
						$recommendations[] = array(
							'type'     => 'ip_threat',
							'severity' => 'high',
							'ip'       => $ip,
							'action'   => 'Block suspicious IP: ' . $ip,
						);
					}
				}
			}

			// Process URL threats
			if ( ! empty( $this->last_analysis['url_threats'] ) ) {
				foreach ( $this->last_analysis['url_threats'] as $url => $threat ) {
					if ( $threat['malicious'] ) {
						$recommendations[] = array(
							'type'     => 'url_threat',
							'severity' => 'high',
							'url'      => $url,
							'action'   => 'Remove malicious URL: ' . $url,
						);
					}
				}
			}

			return $recommendations;

		} finally {
			WP_Security_Performance_Profiler::end_timing( 'generate_recommendations' );
		}
	}

	/**
	 * Generate threat predictions based on patterns
	 */
	public function generate_threat_predictions() {
		WP_Security_Performance_Profiler::start_timing( 'generate_predictions' );

		try {
			$patterns        = $this->threat_intel->get_threat_patterns();
			$current_threats = $this->last_analysis ?? array();

			$predictions = array();

			// Analyze vulnerability patterns
			if ( ! empty( $current_threats['vulnerabilities'] ) ) {
				$predictions['vulnerability_trends'] = $this->analyze_vulnerability_patterns(
					$current_threats['vulnerabilities'],
					$patterns['vulnerability_patterns']
				);
			}

			// Analyze attack patterns
			if ( ! empty( $current_threats['ip_threats'] ) ) {
				$predictions['attack_trends'] = $this->analyze_attack_patterns(
					$current_threats['ip_threats'],
					$patterns['attack_patterns']
				);
			}

			return $predictions;

		} finally {
			WP_Security_Performance_Profiler::end_timing( 'generate_predictions' );
		}
	}

	/**
	 * Generate security report from analysis results
	 */
	private function generate_analysis_report( $results ) {
		return array(
			'summary'         => array(
				'total_vulnerabilities' => count( $results['vulnerabilities'] ?? array() ),
				'total_ip_threats'      => count( $results['ip_threats'] ?? array() ),
				'total_url_threats'     => count( $results['url_threats'] ?? array() ),
				'total_advisories'      => count( $results['advisories'] ?? array() ),
			),
			'details'         => $results,
			'timestamp'       => current_time( 'mysql' ),
			'recommendations' => $this->generate_recommendations(),
		);
	}

	/**
	 * Analyze vulnerability patterns
	 */
	private function analyze_vulnerability_patterns( $vulnerabilities, $patterns ) {
		$trends = array();

		foreach ( $patterns as $pattern ) {
			$matches = array_filter(
				$vulnerabilities,
				function ( $vuln ) use ( $pattern ) {
					return $this->matches_pattern( $vuln, $pattern );
				}
			);

			if ( count( $matches ) >= $pattern['threshold'] ) {
				$trends[] = array(
					'pattern'        => $pattern['name'],
					'confidence'     => $pattern['confidence'],
					'matches'        => count( $matches ),
					'recommendation' => $pattern['recommendation'],
				);
			}
		}

		return $trends;
	}

	/**
	 * Analyze attack patterns
	 */
	private function analyze_attack_patterns( $attacks, $patterns ) {
		$trends = array();

		foreach ( $patterns as $pattern ) {
			$matches = array_filter(
				$attacks,
				function ( $attack ) use ( $pattern ) {
					return $this->matches_pattern( $attack, $pattern );
				}
			);

			if ( count( $matches ) >= $pattern['threshold'] ) {
				$trends[] = array(
					'pattern'        => $pattern['name'],
					'confidence'     => $pattern['confidence'],
					'matches'        => count( $matches ),
					'recommendation' => $pattern['recommendation'],
				);
			}
		}

		return $trends;
	}

	/**
	 * Check if data matches a pattern
	 */
	private function matches_pattern( $data, $pattern ) {
		foreach ( $pattern['criteria'] as $key => $value ) {
			if ( ! isset( $data[ $key ] ) || $data[ $key ] !== $value ) {
				return false;
			}
		}
		return true;
	}
}
