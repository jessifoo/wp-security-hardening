<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}
?>

<div class="wrap">
	<h1>Security Tests</h1>
	
	<div class="notice notice-info">
		<p>Use these tests to verify that each security component is working correctly.</p>
	</div>

	<div class="card">
		<h2>File Integrity Scanner</h2>
		<p>Tests the ability to detect suspicious files.</p>
		<button class="button button-primary" id="test-file-scan">Run Test</button>
		<div id="file-scan-results" class="test-results"></div>
	</div>

	<div class="card">
		<h2>Database Cleaner</h2>
		<p>Tests database cleanup functionality.</p>
		<button class="button button-primary" id="test-db-clean">Run Test</button>
		<div id="db-clean-results" class="test-results"></div>
	</div>

	<div class="card">
		<h2>Login Protection</h2>
		<p>Tests login security features.</p>
		<button class="button button-primary" id="test-login">Run Test</button>
		<div id="login-test-results" class="test-results"></div>
	</div>
</div>

<style>
.card {
	background: #fff;
	border: 1px solid #ccd0d4;
	border-radius: 4px;
	margin-top: 20px;
	padding: 20px;
	box-shadow: 0 1px 1px rgba(0,0,0,0.04);
}

.card h2 {
	margin-top: 0;
}

.test-results {
	margin-top: 15px;
	padding: 10px;
	background: #f8f9fa;
	border-left: 4px solid #ccc;
	display: none;
}

.test-results.success {
	border-left-color: #46b450;
}

.test-results.error {
	border-left-color: #dc3232;
}
</style>

<script>
jQuery(document).ready(function($) {
	function runTest(action, button, resultsDiv) {
		var $button = $(button);
		var $results = $(resultsDiv);
		
		$button.prop('disabled', true).text('Running...');
		$results.hide();
		
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: action,
				_ajax_nonce: '<?php echo wp_create_nonce( 'wp_security_test' ); ?>'
			},
			success: function(response) {
				$button.prop('disabled', false).text('Run Test');
				
				if (response.success) {
					var html = '<h4>Test Passed ✓</h4>';
					html += '<pre>' + JSON.stringify(response.data, null, 2) + '</pre>';
					$results.html(html).removeClass('error').addClass('success').show();
				} else {
					$results.html('<h4>Test Failed ✗</h4><p>' + response.data + '</p>')
							.removeClass('success').addClass('error').show();
				}
			},
			error: function() {
				$button.prop('disabled', false).text('Run Test');
				$results.html('<h4>Test Failed ✗</h4><p>Network error occurred</p>')
						.removeClass('success').addClass('error').show();
			}
		});
	}

	$('#test-file-scan').click(function() {
		runTest('security_test_file_scan', this, '#file-scan-results');
	});

	$('#test-db-clean').click(function() {
		runTest('security_test_db_clean', this, '#db-clean-results');
	});

	$('#test-login').click(function() {
		runTest('security_test_login', this, '#login-test-results');
	});
});
</script>
