<?php if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );} ?>
<div class="wp-security-notifications">
	<?php if ( ! empty( $notifications ) ) : ?>
		<ul class="notification-list">
			<?php foreach ( $notifications as $notification ) : ?>
				<li class="notification-item <?php echo esc_attr( $notification['type'] ); ?>">
					<div class="notification-header">
						<span class="notification-icon"></span>
						<span class="notification-time"><?php echo esc_html( human_time_diff( $notification['timestamp'] ) ); ?> ago</span>
					</div>
					<div class="notification-content">
						<?php echo esc_html( $notification['message'] ); ?>
					</div>
					<?php if ( ! empty( $notification['action'] ) ) : ?>
						<div class="notification-action">
							<a href="<?php echo esc_url( $notification['action']['url'] ); ?>" class="button">
								<?php echo esc_html( $notification['action']['text'] ); ?>
							</a>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php else : ?>
		<div class="no-notifications">
			No new notifications
		</div>
	<?php endif; ?>
</div>
