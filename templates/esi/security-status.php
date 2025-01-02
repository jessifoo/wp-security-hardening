<?php if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );} ?>
<div class="wp-security-status">
	<div class="status-overview">
		<div class="status-item <?php echo esc_attr( $status['overall_status'] ); ?>">
			<span class="status-icon"></span>
			<span class="status-text">Security Status: <?php echo esc_html( $status['overall_status'] ); ?></span>
		</div>
	</div>
	<div class="status-details">
		<div class="metric-item">
			<span class="metric-label">Files Scanned:</span>
			<span class="metric-value"><?php echo esc_html( $status['files_scanned'] ); ?></span>
		</div>
		<div class="metric-item">
			<span class="metric-label">Issues Found:</span>
			<span class="metric-value"><?php echo esc_html( $status['issues_found'] ); ?></span>
		</div>
		<div class="metric-item">
			<span class="metric-label">Last Scan:</span>
			<span class="metric-value"><?php echo esc_html( $status['last_scan'] ); ?></span>
		</div>
	</div>
</div>
