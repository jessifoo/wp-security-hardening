jQuery( document ).ready(
	function ($) {
		// Initialize tooltips
		$( '[data-tooltip]' ).tooltip();

		// Run Security Scan
		$( '#run-scan' ).on(
			'click',
			function () {
				const button = $( this );
				button.prop( 'disabled', true ).text( wpSecurity.strings.scanning );

				$.ajax(
					{
						url: wpSecurity.ajaxUrl,
						type: 'POST',
						data: {
							action: 'wp_security_scan',
							nonce: wpSecurity.nonce
						},
						success: function (response) {
							if (response.success) {
								updateDashboard();
								showNotice( 'success', wpSecurity.strings.success );
							} else {
								showNotice( 'error', response.data.message );
							}
						},
						error: function () {
							showNotice( 'error', wpSecurity.strings.error );
						},
						complete: function () {
							button.prop( 'disabled', false ).text( wpSecurity.strings.runScan );
						}
					}
				);
			}
		);

		// Clean Threat
		$( '.clean-threat' ).on(
			'click',
			function () {
				const button   = $( this );
				const threatId = button.data( 'id' );

				button.prop( 'disabled', true ).text( wpSecurity.strings.cleaning );

				$.ajax(
					{
						url: wpSecurity.ajaxUrl,
						type: 'POST',
						data: {
							action: 'wp_security_clean',
							threat_id: threatId,
							nonce: wpSecurity.nonce
						},
						success: function (response) {
							if (response.success) {
								button.closest( '.threat-item' ).fadeOut();
								updateDashboard();
								showNotice( 'success', wpSecurity.strings.success );
							} else {
								showNotice( 'error', response.data.message );
							}
						},
						error: function () {
							showNotice( 'error', wpSecurity.strings.error );
						},
						complete: function () {
							button.prop( 'disabled', false ).text( wpSecurity.strings.clean );
						}
					}
				);
			}
		);

		// View Threat Details
		$( '.view-threat' ).on(
			'click',
			function () {
				const threatId = $( this ).data( 'id' );

				$.ajax(
					{
						url: wpSecurity.ajaxUrl,
						type: 'POST',
						data: {
							action: 'wp_security_get_threat',
							threat_id: threatId,
							nonce: wpSecurity.nonce
						},
						success: function (response) {
							if (response.success) {
								showThreatModal( response.data );
							} else {
								showNotice( 'error', response.data.message );
							}
						},
						error: function () {
							showNotice( 'error', wpSecurity.strings.error );
						}
					}
				);
			}
		);

		// Manage Quarantine
		$( '#manage-quarantine' ).on(
			'click',
			function () {
				$.ajax(
					{
						url: wpSecurity.ajaxUrl,
						type: 'POST',
						data: {
							action: 'wp_security_get_quarantine',
							nonce: wpSecurity.nonce
						},
						success: function (response) {
							if (response.success) {
								showQuarantineModal( response.data );
							} else {
								showNotice( 'error', response.data.message );
							}
						},
						error: function () {
							showNotice( 'error', wpSecurity.strings.error );
						}
					}
				);
			}
		);

		// Update Dashboard Data
		function updateDashboard() {
			$.ajax(
				{
					url: wpSecurity.ajaxUrl,
					type: 'POST',
					data: {
						action: 'wp_security_get_status',
						nonce: wpSecurity.nonce
					},
					success: function (response) {
						if (response.success) {
							updateStats( response.data );
							updateThreats( response.data.threats );
							updateSystemStatus( response.data.system );
							updateIntelFeed( response.data.intel );
						}
					}
				}
			);
		}

		// Update Statistics
		function updateStats(data) {
			$( '.stat-number' ).each(
				function () {
					const key = $( this ).data( 'stat' );
					if (data[key] !== undefined) {
						$( this ).text( data[key] );
					}
				}
			);

			// Update status card
			const statusCard = $( '.status-card' );
			statusCard.removeClass( 'status-good status-warning status-danger' )
				.addClass( 'status-' + data.status_class );
			statusCard.find( '.status-text' ).text( data.status_text );
		}

		// Update Threats List
		function updateThreats(threats) {
			const list = $( '.threats-list' );
			list.empty();

			if (threats.length === 0) {
				list.append( '<p class="no-threats">' + wpSecurity.strings.noThreats + '</p>' );
				return;
			}

			threats.forEach(
				function (threat) {
					list.append( createThreatItem( threat ) );
				}
			);

			// Reattach event handlers
			attachThreatHandlers();
		}

		// Create Threat Item HTML
		function createThreatItem(threat) {
			return `
			< li class      = "threat-item severity-${threat.severity}" >
				< div class = "threat-header" >
					< span class = "threat-severity" > ${threat.severity} < / span >
					< span class = "threat-time" > ${threat.time_ago} < / span >
				< / div >
				< div class      = "threat-details" >
					< p class = "threat-file" > ${threat.file_path} < / p >
					< p class = "threat-description" > ${threat.description} < / p >
				< / div >
				< div class   = "threat-actions" >
					< button class = "button clean-threat" data - id = "${threat.id}" >
						${wpSecurity.strings.clean}
					< / button >
					< button class = "button button-secondary view-threat" data - id = "${threat.id}" >
						${wpSecurity.strings.view}
					< / button >
				< / div >
			< / li >
			`;
		}

		// Update System Status
		function updateSystemStatus(system) {
			const grid = $( '.status-grid' );
			grid.empty();

			Object.entries( system ).forEach(
				([key, data]) => {
                grid.append(
                        `
						< div class = "status-item status-${data.status}" >
						< span class = "status-label" > ${data.label} < / span >
						< span class = "status-value" > ${data.value} < / span >
						< / div >
						`
					);
				}
			);
		}

		// Update Intelligence Feed
		function updateIntelFeed(intel) {
			const feed = $( '.intel-list' );
			feed.empty();

			if (intel.length === 0) {
				feed.append( '<p class="no-intel">' + wpSecurity.strings.noIntel + '</p>' );
				return;
			}

			intel.forEach(
				function (item) {
					feed.append(
						`
						< li class = "intel-item" >
						< span class = "intel-time" > ${item.time_ago} < / span >
						< p class = "intel-description" > ${item.description} < / p >
						< span class = "intel-source" > ${item.source} < / span >
						< / li >
						`
					);
				}
			);
		}

		// Show Notice
		function showNotice(type, message) {
			const notice = $( '<div>' )
			.addClass( 'notice notice-' + type )
			.addClass( 'is-dismissible' )
			.append( $( '<p>' ).text( message ) );

			$( '.wp-security-dashboard > h1' ).after( notice );

			// Auto dismiss after 5 seconds
			setTimeout(
				function () {
					notice.fadeOut(
						function () {
							$( this ).remove();
						}
					);
				},
				5000
			);
		}

		// Show Threat Modal
		function showThreatModal(data) {
			const modal = $(
				`
				< div class = "wp-security-modal" >
				< div class = "modal-content" >
					< h2 > Threat Details < / h2 >
					< div class = "threat-info" >
						< p > < strong > File: < / strong > ${data.file_path} < / p >
						< p > < strong > Detected: < / strong > ${data.detected_time} < / p >
						< p > < strong > Severity: < / strong > ${data.severity} < / p >
						< p > < strong > Description: < / strong > ${data.description} < / p >
						< pre class = "code-preview" > ${data.code_preview} < / pre >
					< / div >
					< div class     = "modal-actions" >
						< button class = "button button-primary clean-threat" data - id = "${data.id}" >
							${wpSecurity.strings.clean}
						< / button >
						< button class = "button button-secondary close-modal" >
							${wpSecurity.strings.close}
						< / button >
					< / div >
				< / div >
				< / div >
				`
			);

			$( 'body' ).append( modal );
			modal.fadeIn();

			// Close modal events
			modal.find( '.close-modal' ).on(
				'click',
				function () {
					modal.fadeOut(
						function () {
							$( this ).remove();
						}
					);
				}
			);

			// Close on escape key
			$( document ).on(
				'keyup',
				function (e) {
					if (e.key === "Escape") {
						modal.fadeOut(
							function () {
								$( this ).remove();
							}
						);
					}
				}
			);
		}

		// Show Quarantine Modal
		function showQuarantineModal(data) {
			const modal     = $(
				`
				< div class = "wp-security-modal" >
				< div class = "modal-content" >
					< h2 > Quarantined Files < / h2 >
					< div class = "quarantine-stats" >
						< p > < strong > Total Files: < / strong > ${data.total_files} < / p >
						< p > < strong > Total Size: < / strong > ${data.total_size} < / p >
					< / div >
					< div class = "quarantine-list" >
						${createQuarantineList( data.files )}
					< / div >
					< div class = "modal-actions" >
						< button class = "button button-secondary close-modal" >
							${wpSecurity.strings.close}
						< / button >
					< / div >
				< / div >
				< / div >
				`
			);

			$( 'body' ).append( modal );
			modal.fadeIn();

			// Close modal events
			modal.find( '.close-modal' ).on(
				'click',
				function () {
					modal.fadeOut(
						function () {
							$( this ).remove();
						}
					);
				}
			);
		}

		// Create Quarantine List HTML
		function createQuarantineList(files) {
			if (files.length === 0) {
				return '<p class="no-files">No quarantined files</p>';
			}

			return `
			< table class = "wp-list-table widefat" >
				< thead >
					< tr >
						< th > File < / th >
						< th > Quarantined < / th >
						< th > Size < / th >
						< th > Actions < / th >
					< / tr >
				< / thead >
				< tbody >
					${files.map(
						file => `
						< tr >
							< td > ${file.name} < / td >
							< td > ${file.date} < / td >
							< td > ${file.size} < / td >
							< td >
								< button class = "button restore-file" data - id = "${file.id}" >
									Restore
								< / button >
								< button class = "button button-link-delete delete-file" data - id = "${file.id}" >
									Delete
								< / button >
							< / td >
						< / tr >
						`
					).join( '' )}
				< / tbody >
			< / table >
			`;
		}

		// Start periodic updates
		setInterval( updateDashboard, 60000 ); // Update every minute
	}
);
