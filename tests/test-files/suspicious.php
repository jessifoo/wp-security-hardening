<?php
// This is a test file with suspicious content for testing the security scanner
eval( base64_decode( 'ZWNobyAiaGVsbG8iOw==' ) ); // Suspicious eval
$dangerous = $_GET['user_input']; // Unsanitized input
require $dangerous; // Dangerous include
