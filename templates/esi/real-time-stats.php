<?php if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );} ?>
<div class="wp-security-real-time-stats">
	<div class="stats-grid">
		<div class="stat-item memory">
			<div class="stat-label">Memory Usage</div>
			<div class="stat-value"><?php echo esc_html( $stats['memory_usage'] ); ?></div>
			<div class="stat-chart">
				<div class="chart-bar" style="width: <?php echo esc_attr( $stats['memory_percentage'] ); ?>%"></div>
			</div>
		</div>
		<div class="stat-item cpu">
			<div class="stat-label">CPU Load</div>
			<div class="stat-value"><?php echo esc_html( $stats['cpu_load'] ); ?></div>
			<div class="stat-chart">
				<div class="chart-bar" style="width: <?php echo esc_attr( $stats['cpu_percentage'] ); ?>%"></div>
			</div>
		</div>
		<div class="stat-item requests">
			<div class="stat-label">Requests/min</div>
			<div class="stat-value"><?php echo esc_html( $stats['requests_per_minute'] ); ?></div>
			<div class="stat-trend <?php echo esc_attr( $stats['requests_trend'] ); ?>">
				<?php echo esc_html( $stats['requests_change'] ); ?>%
			</div>
		</div>
		<div class="stat-item security">
			<div class="stat-label">Security Events</div>
			<div class="stat-value"><?php echo esc_html( $stats['security_events'] ); ?></div>
			<div class="stat-trend <?php echo esc_attr( $stats['events_trend'] ); ?>">
				<?php echo esc_html( $stats['events_change'] ); ?>%
			</div>
		</div>
	</div>
</div>
