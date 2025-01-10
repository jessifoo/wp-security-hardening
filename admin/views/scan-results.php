<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$scan_results = get_transient( 'wp_security_scan_results' );
$log_entries  = WP_Security\Core\Logger::get_instance()->get_recent_logs( 'scanner', 50 );
?>

<div class="wrap">
	<h1>Security Scan Results</h1>

	<?php if ( $scan_results ) : ?>
		<div class="scan-summary card">
			<h2>Scan Summary</h2>
			<table class="widefat">
				<tr>
					<th>Files Checked</th>
					<td><?php echo esc_html( $scan_results->getMetadata( 'files_checked' ) ); ?></td>
				</tr>
				<tr>
					<th>Malicious Files Removed</th>
					<td><?php echo esc_html( $scan_results->getMetadata( 'files_removed' ) ); ?></td>
				</tr>
				<tr>
					<th>Core Files Restored</th>
					<td><?php echo esc_html( $scan_results->getMetadata( 'files_restored' ) ); ?></td>
				</tr>
				<tr>
					<th>Scan Duration</th>
					<td><?php echo esc_html( $scan_results->getMetadata( 'duration' ) . ' seconds' ); ?></td>
				</tr>
			</table>
		</div>

		<?php if ( $scan_results->hasIssues() ) : ?>
			<div class="scan-issues card">
				<h2>Detected Issues</h2>
				<table class="widefat">
					<thead>
						<tr>
							<th>File</th>
							<th>Issue Type</th>
							<th>Status</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $scan_results->getIssues() as $issue ) : ?>
							<tr>
								<td><?php echo esc_html( $issue['file'] ); ?></td>
								<td><?php echo esc_html( $issue['type'] ); ?></td>
								<td>
									<?php
									$status_class = '';
									switch ( $issue['status'] ) {
										case 'cleaned':
											$status_class = 'success';
											break;
										case 'quarantined':
											$status_class = 'warning';
											break;
										case 'failed':
											$status_class = 'error';
											break;
									}
									?>
									<span class="status-<?php echo esc_attr( $status_class ); ?>">
										<?php echo esc_html( ucfirst( $issue['status'] ) ); ?>
									</span>
								</td>
								<td>
									<?php if ( $issue['status'] === 'quarantined' ) : ?>
										<form method="post" style="display: inline;">
											<?php wp_nonce_field( 'wp_security_restore_file' ); ?>
											<input type="hidden" name="file" value="<?php echo esc_attr( $issue['file'] ); ?>">
											<button type="submit" name="restore_file" class="button button-small">
												Restore
											</button>
										</form>
										<form method="post" style="display: inline;">
											<?php wp_nonce_field( 'wp_security_delete_file' ); ?>
											<input type="hidden" name="file" value="<?php echo esc_attr( $issue['file'] ); ?>">
											<button type="submit" name="delete_file" class="button button-small">
												Delete Permanently
											</button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	<?php endif; ?>

	<div class="scan-log card">
		<h2>Scan Log</h2>
		<div class="log-entries" style="max-height: 400px; overflow-y: auto;">
			<?php if ( ! empty( $log_entries ) ) : ?>
				<table class="widefat">
					<thead>
						<tr>
							<th>Time</th>
							<th>Level</th>
							<th>Message</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $log_entries as $entry ) : ?>
							<tr class="log-level-<?php echo esc_attr( strtolower( $entry['level'] ) ); ?>">
								<td><?php echo esc_html( $entry['time'] ); ?></td>
								<td><?php echo esc_html( $entry['level'] ); ?></td>
								<td><?php echo esc_html( $entry['message'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p>No log entries found.</p>
			<?php endif; ?>
		</div>
	</div>
</div>

<style>
.card {
	background: #fff;
	border: 1px solid #ccd0d4;
	padding: 20px;
	margin-top: 20px;
	box-shadow: 0 1px 1px rgba(0,0,0,.04);
}

.scan-summary table {
	margin-top: 10px;
}

.status-success {
	color: #46b450;
}

.status-warning {
	color: #ffb900;
}

.status-error {
	color: #dc3232;
}

.log-level-info {
	color: #0073aa;
}

.log-level-warning {
	color: #ffb900;
}

.log-level-error {
	color: #dc3232;
}

.log-entries table {
	margin-top: 10px;
}

.button-small {
	margin: 0 5px;
}
</style>
