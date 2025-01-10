<?php
namespace WP_Security\Admin;

class SecurityDashboard {
	private $template_loader;
	private $security_service;

	public function renderDashboard() {
		$scan_results = $this->security_service->getLatestScanResults();
		$threats      = $this->security_service->getActivethreats();

		$this->template_loader->render(
			'dashboard',
			array(
				'scan_results' => $scan_results,
				'threats'      => $threats,
			)
		);
	}
}
