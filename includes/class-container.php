<?php
namespace WP_Security;

class Container {
	private $services  = array();
	private $factories = array();

	public function register( $id, $factory ) {
		$this->factories[ $id ] = $factory;
	}

	public function get( $id ) {
		if ( ! isset( $this->services[ $id ] ) ) {
			if ( ! isset( $this->factories[ $id ] ) ) {
				throw new \Exception( "Service $id not found" );
			}
			$this->services[ $id ] = $this->factories[ $id ]( $this );
		}
		return $this->services[ $id ];
	}
}
