<?php if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );} ?>
<div class="wp-security-user-status">
	<div class="status-header">
		<span class="user-avatar"><?php echo get_avatar( $user->ID, 32 ); ?></span>
		<span class="user-name"><?php echo esc_html( $user->display_name ); ?></span>
	</div>
	<div class="status-details">
		<div class="last-login">
			Last Login: <?php echo esc_html( get_user_meta( $user->ID, 'last_login', true ) ); ?>
		</div>
		<div class="security-level">
			Security Level: <?php echo esc_html( WP_Security_User_Manager::get_instance()->get_user_security_level( $user->ID ) ); ?>
		</div>
	</div>
</div>
