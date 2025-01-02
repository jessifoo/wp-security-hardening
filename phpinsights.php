<?php

declare(strict_types=1);

return array(
	'preset'       => 'wordpress',
	'ide'          => 'vscode',

	'exclude'      => array(
		'vendor',
		'tests',
		'node_modules',
	),

	'add'          => array(),

	'remove'       => array(
		// WordPress often requires static access
		SlevomatCodingStandard\Sniffs\Classes\DisallowLateStaticBindingForConstantsSniff::class,
		PHP_CodeSniffer\Standards\Generic\Sniffs\PHP\NoSilencedErrorsSniff::class,

		// WordPress coding standards differ from PSR
		PhpCsFixer\Fixer\ClassNotation\VisibilityRequiredFixer::class,
		PhpCsFixer\Fixer\ClassNotation\OrderedClassElementsFixer::class,
	),

	'config'       => array(
		PHP_CodeSniffer\Standards\Generic\Sniffs\Files\LineLengthSniff::class => array(
			'lineLimit'         => 120,
			'absoluteLineLimit' => 140,
		),

		PhpCsFixer\Fixer\Import\OrderedImportsFixer::class => array(
			'imports_order'  => array( 'class', 'function', 'const' ),
			'sort_algorithm' => 'alpha',
		),

		SlevomatCodingStandard\Sniffs\Functions\FunctionLengthSniff::class => array(
			'maxLinesLength' => 50,
		),

		SlevomatCodingStandard\Sniffs\Commenting\DocCommentSpacingSniff::class => array(
			'linesCountBetweenDifferentAnnotationsTypes' => 1,
		),
	),

	'requirements' => array(
		'min-quality'            => 90,
		'min-complexity'         => 85,
		'min-architecture'       => 90,
		'min-style'              => 90,
		'disable-security-check' => false,
	),
);
