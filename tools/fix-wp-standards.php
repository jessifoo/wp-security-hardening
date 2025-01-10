<?php

/**
 * WordPress Coding Standards Auto-fixer
 *
 * Usage:
 * - Single file: php fix-wp-standards.php path/to/file.php
 * - All files: php fix-wp-standards.php --all
 */
function fix_file( $file, $dry_run = false ) {
	if ( ! file_exists( $file ) ) {
		echo "Skipping non-existent file: $file\n";
		return;
	}

	$original = file_get_contents( $file );
	$content  = $original;

	// Common fixes
	$fixes = array(
		// WordPress spacing before parentheses
		'/([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\(/' => '$1 (',
		'/\)\s*\{/'                                      => ') {',
		'/if\(/'                                         => 'if (',
		'/foreach\(/'                                    => 'foreach (',
		'/while\(/'                                      => 'while (',
		'/catch\(/'                                      => 'catch (',
		'/switch\(/'                                     => 'switch (',

		// WordPress array syntax
		'/\[\s*\]/'                                      => 'array()',
		'/\[([\s\S]*?)\]/'                               => 'array($1)',

		// WordPress spacing around operators
		'/([=!<>]+)==/'                                  => '$1 ==',
		'/==([^\s])/'                                    => '== $1',
		'/\s*=\s*/'                                      => ' = ',
		'/\s*\+=\s*/'                                    => ' += ',
		'/\s*-=\s*/'                                     => ' -= ',
		'/\s*\*=\s*/'                                    => ' *= ',
		'/\s*\/=\s*/'                                    => ' /= ',
		'/\s*%=\s*/'                                     => ' %= ',
		'/\s*&&\s*/'                                     => ' && ',
		'/\s*\|\|\s*/'                                   => ' || ',

		// WordPress array alignment
		'/=>(\S)/'                                       => '=> $1',

		// WordPress comment spacing
		'/\/\/\S/'                                       => '// ',
		'/\/\*\S/'                                       => '/* ',
		'/\S\*\//'                                       => ' */',

		// WordPress comma spacing
		'/,(\S)/'                                        => ', $1',

		// WordPress concatenation spacing
		'/\s*\.\s*/'                                     => ' . ',

		// WordPress type hints in docblocks
		'/\@param\s+([a-zA-Z_\\\]+)\s+\$/'               => '@param $1 $',
		'/\@return\s+([a-zA-Z_\\\]+)/'                   => '@return $1',

		// WordPress hook documentation
		'/do_action\(\s*\'([^\']+)\'/'                   => function ( $matches ) {
			return "/**\n * Fires when {$matches[1]} occurs\n *\n * @param string \$param Description\n */\ndo_action( '{$matches[1]}'";
		},

		// WordPress filter documentation
		'/apply_filters\(\s*\'([^\']+)\'/'               => function ( $matches ) {
			return "/**\n * Filters {$matches[1]}\n *\n * @param mixed \$value The value to filter\n */\napply_filters( '{$matches[1]}'";
		},

		// WordPress method visibility
		'/^(\s*)function\s/'                             => '$1public function ',

		// WordPress property visibility
		'/^(\s*)(var|\$)/'                               => '$1private $',

		// WordPress method naming
		'/function ([a-z]+[A-Z])/'                       => 'function $1_',

		// WordPress constant naming
		'/const\s+([a-z])/'                              => 'const ' . strtoupper( '$1' ),

		// Fix WordPress docblock format
		'/\*\s+@(param|return|var)\s+([A-Za-z0-9_|\\\\]+)/' => '* @$1 $2',

		// Fix WordPress array syntax with proper alignment
		'/\[\s*\]/'                                      => 'array()',
		'/\[\s*([^\]]+)\s*\]/'                           => 'array($1)',

		// Fix WordPress method spacing
		'/function\s*\(/'                                => 'function (',
		'/\)\s*\{/'                                      => ') {',

		// Fix WordPress hook spacing
		'/do_action\s*\(/'                               => 'do_action(',
		'/apply_filters\s*\(/'                           => 'apply_filters(',

		// Fix WordPress variable declaration spacing
		'/private\s+\$/'                                 => 'private $',
		'/protected\s+\$/'                               => 'protected $',
		'/public\s+\$/'                                  => 'public $',

		// Fix WordPress class declaration
		'/class\s+(\w+)\s*\{/'                           => 'class $1 {',

		// Fix WordPress interface declaration
		'/interface\s+(\w+)\s*\{/'                       => 'interface $1 {',

		// Fix WordPress trait declaration
		'/trait\s+(\w+)\s*\{/'                           => 'trait $1 {',
	);

	// Fix class docblocks
	$content = preg_replace_callback(
		'/^class\s+(\w+)(?!\s*\{[^}]*\*\s*@package)/m',
		function ( $matches ) {
			return "/**\n * " . $matches[1] . " class\n *\n * @package WP_Security\n */\nclass " . $matches[1];
		},
		$content
	);

	// Fix method docblocks
	$content = preg_replace_callback(
		'/^\s*(?:public|private|protected)\s+function\s+(\w+)\s*\([^)]*\)\s*(?!\{[^}]*\*\s*@)/m',
		function ( $matches ) {
			return "\t/**\n\t * " . ucfirst( str_replace( '_', ' ', $matches[1] ) ) . "\n\t *\n\t * @return void\n\t */\n\t" . $matches[0];
		},
		$content
	);

	// Fix property docblocks
	$content = preg_replace_callback(
		'/^\s*(?:private|protected|public)\s+(\$\w+)(?!\s*;[^;]*\*\s*@)/m',
		function ( $matches ) {
			return "\t/**\n\t * " . ucfirst( str_replace( '_', ' ', ltrim( $matches[1], '$' ) ) ) . "\n\t *\n\t * @var mixed\n\t */\n\t" . $matches[0];
		},
		$content
	);

	// Apply all fixes
	$content = preg_replace( array_keys( $fixes ), array_values( $fixes ), $content );

	// Fix indentation
	$lines        = explode( "\n", $content );
	$fixed_lines  = array();
	$indent_level = 0;
	foreach ( $lines as $line ) {
		$line = rtrim( $line );
		if ( preg_match( '/^[\t ]*\}/', $line ) ) {
			--$indent_level;
		}
		$fixed_lines[] = str_repeat( "\t", max( 0, $indent_level ) ) . ltrim( $line );
		if ( preg_match( '/\{[\t ]*$/', $line ) ) {
			++$indent_level;
		}
	}
	$content = implode( "\n", $fixed_lines );

	if ( $dry_run ) {
		if ( $content !== $original ) {
			echo "Would fix: $file\n";
			echo "Diff:\n";
			echo diff( $original, $content );
		}
		return;
	}

	// Write back
	file_put_contents( $file, $content );
	echo "Fixed: $file\n";
}

function fix_directory( $dir ) {
	if ( ! is_dir( $dir ) ) {
		echo "Directory not found: $dir\n";
		return;
	}

	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $dir )
	);

	foreach ( $iterator as $file ) {
		if ( $file->isFile() && $file->getExtension() === 'php' ) {
			fix_file( $file->getPathname() );
		}
	}
}

// Main execution
if ( $argc < 2 ) {
	die( "Usage: php fix-wp-standards.php [file|--all]\n" );
}

if ( $argv[1] === '--all' ) {
	fix_directory( __DIR__ . '/../includes' );
} else {
	fix_file( $argv[1] );
}

// Add better docblock generation
function generate_method_docblock( $method_name, $params = array() ) {
	$lines = array(
		"\t/**",
		"\t * " . ucfirst( str_replace( '_', ' ', $method_name ) ),
		"\t *",
	);

	foreach ( $params as $param => $type ) {
		$lines[] = "\t * @param {$type} \${$param} Description";
	}

	$lines[] = "\t * @return void";
	$lines[] = "\t */";

	return implode( "\n", $lines );
}

// Add dry-run option
if ( $argv[1] === '--dry-run' ) {
	fix_directory( __DIR__ . '/../includes', true );
	exit;
}
