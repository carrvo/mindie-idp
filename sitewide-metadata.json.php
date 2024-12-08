<?php
$issuer = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST'];
$meta = [
	"issuer" => $issuer,
	"authorization_endpoint" => "$issuer/selfauth/index",
	"token_endpoint" => "$issuer/selfauth/token?action=authorize",
	"introspection_endpoint" => "$issuer/selfauth/token?action=introspect",
	"response_types_supported" => ["code"],
	"response_modes_supported" => ["query"],
	"grant_types_supported" => ["authorization_code"],
	"token_endpoint_auth_methods_supported" => ["client_secret_basic"],
	"introspection_endpoint_auth_methods_supported" => ["client_secret_basic"],
	"service_documentation" => "https://indieauth.spec.indieweb.org/#indieauth-server-metadata-li-11",
	"code_challenge_methods_supported" => ["S256"],
];
exit(json_encode($meta));
?>
