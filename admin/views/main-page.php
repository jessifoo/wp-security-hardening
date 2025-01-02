<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap">
	<h1>WordPress Security Hardening</h1>
	
	<?php settings_errors( 'wp_security' ); ?>
	
	<div class="card">
		<h2>Malware Scanner</h2>
		<p>Scan your WordPress installation for malware, suspicious files, and corrupted core files.</p>
		
		<form method="post" action="">
			<?php wp_nonce_field( 'wp_security_scan' ); ?>
			<p>
				<button type="submit" name="run_scan" class="button button-primary">
					Run Security Scan
				</button>
			</p>
		</form>
	</div>
	
	<div class="card">
		<h2>Settings</h2>
		<form method="post" action="options.php">
			<?php
				settings_fields( 'wp_security_settings' );
				$settings = WP_Security_Settings::get_instance();
				$options  = $settings->get_all();
			?>
			
			<table class="form-table">
				<tr>
					<th scope="row">Scan Schedule</th>
					<td>
						<select name="wp_security_settings[scan_schedule]">
							<option value="hourly" <?php selected( $options['scan_schedule'], 'hourly' ); ?>>Hourly</option>
							<option value="daily" <?php selected( $options['scan_schedule'], 'daily' ); ?>>Daily</option>
							<option value="weekly" <?php selected( $options['scan_schedule'], 'weekly' ); ?>>Weekly</option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row">Auto Clean</th>
					<td>
						<label>
							<input type="checkbox" name="wp_security_settings[auto_clean]" value="1" <?php checked( $options['auto_clean'] ); ?>>
							Automatically remove detected malware
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Notifications</th>
					<td>
						<label>
							<input type="checkbox" name="wp_security_settings[notify_admin]" value="1" <?php checked( $options['notify_admin'] ); ?>>
							Email admin when threats are detected
						</label>
					</td>
				</tr>
			</table>
			
			<?php submit_button(); ?>
		</form>
	</div>
</div>
