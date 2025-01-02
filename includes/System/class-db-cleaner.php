<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_DB_Cleaner {
	private $last_cleanup_option = 'wp_security_last_db_cleanup';
	private $malware_patterns    = array(
		// Common malware patterns in posts/comments
		'eval_pattern'   => '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|strrev)\s*\([^\)]+\)\s*\)/i',
		'iframe_spam'    => '/<iframe[^>]*src\s*=\s*[\'"]https?:\/\/[^\'"]+[\'"]/i',
		'js_redirect'    => '/window\.location\s*=|document\.location\s*=|location\.href\s*=/i',
		'hidden_links'   => '/<div[^>]*style\s*=\s*[\'"][^"\']*display\s*:\s*none[^"\']*[\'"][^>]*>/i',
		'base64_content' => '/[a-zA-Z0-9+\/]{50,}={0,2}/',
		'pharma_spam'    => '/(?:viagra|cialis|levitra|pharmacy|prescription|medication)\s+(?:online|cheap|discount|buy)/i',
		'seo_spam'       => '/<a[^>]*href\s*=\s*[\'"]https?:\/\/[^\'"]+[\'"]\s*(?:rel\s*=\s*[\'"](?:dofollow|sponsored)[\'"]\s*)?>[^<]*(?:casino|poker|bet|loan|mortgage|viagra|cialis)[^<]*<\/a>/i',
		'encoded_php'    => '/\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}/',
		'malicious_js'   => '/<script[^>]*>[^<]*(?:document\.write|unescape|fromCharCode|eval|setTimeout|setInterval)[^<]*<\/script>/i',
	);

	public function __construct() {
		add_action( 'wp_security_daily_cleanup', array( $this, 'cleanup' ) );
		add_action( 'wp_security_db_cleanup', array( $this, 'auto_clean_database' ) );
		if ( ! wp_next_scheduled( 'wp_security_db_cleanup' ) ) {
			wp_schedule_event( time(), 'sixhours', 'wp_security_db_cleanup' );
		}
	}

	public function cleanup() {
		global $wpdb;

		$start_time = time();
		$cleaned    = array();

		// Start transaction
		$wpdb->query( 'START TRANSACTION' );

		try {
			// 1. Post revisions
			$cleaned['revisions'] = $this->clean_revisions();

			// 2. Auto-drafts
			$cleaned['auto_drafts'] = $this->clean_auto_drafts();

			// 3. Trashed posts
			$cleaned['trash'] = $this->clean_trash();

			// 4. Orphaned post meta
			$cleaned['orphaned_meta'] = $this->clean_orphaned_meta();

			// 5. Orphaned term relationships
			$cleaned['orphaned_relationships'] = $this->clean_orphaned_relationships();

			// 6. Expired transients
			$cleaned['transients'] = $this->clean_transients();

			// 7. Spam comments
			$cleaned['spam'] = $this->clean_spam();

			// 8. Unused terms
			$cleaned['unused_terms'] = $this->clean_unused_terms();

			// 9. Optimize tables
			$this->optimize_tables();

			$wpdb->query( 'COMMIT' );
		} catch ( Exception $e ) {
			$wpdb->query( 'ROLLBACK' );
			error_log( 'DB Cleanup failed: ' . $e->getMessage() );
			return false;
		}

		update_option(
			$this->last_cleanup_option,
			array(
				'time'    => $start_time,
				'results' => $cleaned,
			)
		);

		return $cleaned;
	}

	public function auto_clean_database() {
		global $wpdb;

		// Clean posts
		$this->clean_posts();

		// Clean comments
		$this->clean_comments();

		// Clean options
		$this->clean_options();

		// Clean user meta
		$this->clean_user_meta();

		// Clean transients
		$this->clean_transients();

		// Optimize tables
		$this->optimize_tables();
	}

	private function clean_revisions() {
		global $wpdb;

		$query = "DELETE FROM $wpdb->posts WHERE post_type = 'revision'";
		return $wpdb->query( $query );
	}

	private function clean_auto_drafts() {
		global $wpdb;

		$query = $wpdb->prepare(
			"DELETE FROM $wpdb->posts WHERE post_status = 'auto-draft' 
             OR (post_status = 'draft' AND post_modified < %s)",
			date( 'Y-m-d', strtotime( '-30 days' ) )
		);

		return $wpdb->query( $query );
	}

	private function clean_trash() {
		global $wpdb;

		$query = $wpdb->prepare(
			"DELETE FROM $wpdb->posts WHERE post_status = 'trash' 
             AND post_modified < %s",
			date( 'Y-m-d', strtotime( '-30 days' ) )
		);

		return $wpdb->query( $query );
	}

	private function clean_orphaned_meta() {
		global $wpdb;

		$query = "DELETE pm FROM $wpdb->postmeta pm 
                 LEFT JOIN $wpdb->posts p ON p.ID = pm.post_id 
                 WHERE p.ID IS NULL";

		return $wpdb->query( $query );
	}

	private function clean_orphaned_relationships() {
		global $wpdb;

		$query = "DELETE tr FROM $wpdb->term_relationships tr 
                 LEFT JOIN $wpdb->posts p ON p.ID = tr.object_id 
                 WHERE p.ID IS NULL";

		return $wpdb->query( $query );
	}

	private function clean_transients() {
		global $wpdb;

		$time  = time();
		$query = $wpdb->prepare(
			"DELETE FROM $wpdb->options 
             WHERE option_name LIKE %s 
             AND option_value < %d",
			$wpdb->esc_like( '_transient_timeout_' ) . '%',
			$time
		);

		$wpdb->query( $query );

		$query = $wpdb->prepare(
			"DELETE FROM $wpdb->options 
             WHERE option_name LIKE %s",
			$wpdb->esc_like( '_transient_' ) . '%'
		);

		return $wpdb->query( $query );
	}

	private function clean_spam() {
		global $wpdb;

		$query = "DELETE FROM $wpdb->comments WHERE comment_approved = 'spam'";
		return $wpdb->query( $query );
	}

	private function clean_unused_terms() {
		global $wpdb;

		// Remove unused terms
		$query = "DELETE t, tt FROM $wpdb->terms t 
                 LEFT JOIN $wpdb->term_taxonomy tt ON t.term_id = tt.term_id 
                 LEFT JOIN $wpdb->term_relationships tr ON tt.term_taxonomy_id = tr.term_taxonomy_id 
                 WHERE tr.object_id IS NULL";

		return $wpdb->query( $query );
	}

	private function optimize_tables() {
		global $wpdb;

		$tables = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );

		foreach ( $tables as $table ) {
			$wpdb->query( "OPTIMIZE TABLE $table" );
		}
	}

	private function clean_posts() {
		global $wpdb;

		// Get all posts and pages
		$posts = $wpdb->get_results(
			"
            SELECT ID, post_content, post_title, post_excerpt
            FROM {$wpdb->posts}
            WHERE post_status != 'trash'
        "
		);

		foreach ( $posts as $post ) {
			$content_cleaned = false;
			$title_cleaned   = false;
			$excerpt_cleaned = false;

			// Clean content
			$new_content = $post->post_content;
			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_content ) ) {
					$new_content     = preg_replace( $pattern, '', $new_content );
					$content_cleaned = true;
				}
			}

			// Clean title
			$new_title = $post->post_title;
			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_title ) ) {
					$new_title     = preg_replace( $pattern, '', $new_title );
					$title_cleaned = true;
				}
			}

			// Clean excerpt
			$new_excerpt = $post->post_excerpt;
			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_excerpt ) ) {
					$new_excerpt     = preg_replace( $pattern, '', $new_excerpt );
					$excerpt_cleaned = true;
				}
			}

			// Update if cleaned
			if ( $content_cleaned || $title_cleaned || $excerpt_cleaned ) {
				$wpdb->update(
					$wpdb->posts,
					array(
						'post_content' => $new_content,
						'post_title'   => $new_title,
						'post_excerpt' => $new_excerpt,
					),
					array( 'ID' => $post->ID )
				);
			}
		}
	}

	private function clean_comments() {
		global $wpdb;

		// Get all non-spam comments
		$comments = $wpdb->get_results(
			"
            SELECT comment_ID, comment_content, comment_author_url
            FROM {$wpdb->comments}
            WHERE comment_approved != 'spam'
        "
		);

		foreach ( $comments as $comment ) {
			$content_cleaned = false;
			$url_cleaned     = false;

			// Clean content
			$new_content = $comment->comment_content;
			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_content ) ) {
					$new_content     = preg_replace( $pattern, '', $new_content );
					$content_cleaned = true;
				}
			}

			// Clean author URL
			$new_url = $comment->comment_author_url;
			if ( preg_match( '/^https?:\/\/[^\'"]+$/i', $new_url ) ) {
				$response = wp_remote_head( $new_url );
				if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) >= 400 ) {
					$new_url     = '';
					$url_cleaned = true;
				}
			}

			// Update if cleaned
			if ( $content_cleaned || $url_cleaned ) {
				$wpdb->update(
					$wpdb->comments,
					array(
						'comment_content'    => $new_content,
						'comment_author_url' => $new_url,
					),
					array( 'comment_ID' => $comment->comment_ID )
				);
			}
		}
	}

	private function clean_options() {
		global $wpdb;

		// Get all options
		$options = $wpdb->get_results(
			"
            SELECT option_id, option_name, option_value
            FROM {$wpdb->options}
            WHERE option_name NOT LIKE '_transient%'
            AND option_name NOT LIKE '_site_transient%'
        "
		);

		foreach ( $options as $option ) {
			if ( is_serialized( $option->option_value ) ) {
				continue; // Skip serialized data for now
			}

			$cleaned   = false;
			$new_value = $option->option_value;

			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_value ) ) {
					$new_value = preg_replace( $pattern, '', $new_value );
					$cleaned   = true;
				}
			}

			if ( $cleaned ) {
				$wpdb->update(
					$wpdb->options,
					array( 'option_value' => $new_value ),
					array( 'option_id' => $option->option_id )
				);
			}
		}
	}

	private function clean_user_meta() {
		global $wpdb;

		// Get all user meta
		$user_meta = $wpdb->get_results(
			"
            SELECT umeta_id, meta_value
            FROM {$wpdb->usermeta}
            WHERE meta_key NOT LIKE '%_capabilities'
            AND meta_key NOT LIKE '%_user_level'
        "
		);

		foreach ( $user_meta as $meta ) {
			if ( is_serialized( $meta->meta_value ) ) {
				continue; // Skip serialized data for now
			}

			$cleaned   = false;
			$new_value = $meta->meta_value;

			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( $pattern, $new_value ) ) {
					$new_value = preg_replace( $pattern, '', $new_value );
					$cleaned   = true;
				}
			}

			if ( $cleaned ) {
				$wpdb->update(
					$wpdb->usermeta,
					array( 'meta_value' => $new_value ),
					array( 'umeta_id' => $meta->umeta_id )
				);
			}
		}
	}

	public function get_db_stats() {
		global $wpdb;

		$stats = array();

		// Get table sizes
		$tables = $wpdb->get_results( "SHOW TABLE STATUS LIKE '{$wpdb->prefix}%'" );

		$total_size     = 0;
		$total_overhead = 0;

		foreach ( $tables as $table ) {
			$size        = ( $table->Data_length + $table->Index_length );
			$total_size += $size;

			if ( $table->Data_free > 0 ) {
				$total_overhead += $table->Data_free;
			}

			$stats['tables'][] = array(
				'name'     => $table->Name,
				'rows'     => $table->Rows,
				'size'     => size_format( $size ),
				'overhead' => size_format( $table->Data_free ),
			);
		}

		$stats['total_size']     = size_format( $total_size );
		$stats['total_overhead'] = size_format( $total_overhead );

		// Get counts of cleanup-able items
		$stats['cleanup_potential'] = array(
			'revisions'   => $wpdb->get_var(
				"SELECT COUNT(*) FROM $wpdb->posts WHERE post_type = 'revision'"
			),
			'auto_drafts' => $wpdb->get_var(
				"SELECT COUNT(*) FROM $wpdb->posts WHERE post_status = 'auto-draft'"
			),
			'trash'       => $wpdb->get_var(
				"SELECT COUNT(*) FROM $wpdb->posts WHERE post_status = 'trash'"
			),
			'spam'        => $wpdb->get_var(
				"SELECT COUNT(*) FROM $wpdb->comments WHERE comment_approved = 'spam'"
			),
		);

		return $stats;
	}

	public function get_last_cleanup() {
		return get_option( $this->last_cleanup_option );
	}
}
