<?php
namespace WP_Security\Validation;

class InputValidator {
	public function validateScanOptions( array $options ): array {
		return array_intersect_key(
			$options,
			array_flip(
				array(
					'depth',
					'file_types',
					'exclusions',
				)
			)
		);
	}
}
