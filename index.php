<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
// Start the session
session_start();
include("vendor/autoload.php");

$action = (@isset($_GET['action'])) ? $_GET['action'] : "default";


set_exception_handler(function ($e) {
	echo ($e->getMessage());
	exit('Something weird mysql happened'); //something a user can understand
});

$dsn = "mysql:host=localhost;dbname=fido2;charset=utf8mb4";
$options = [
	PDO::ATTR_EMULATE_PREPARES   => false, // turn off emulation mode for "real" prepared statements
	PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, //turn on errors in the form of exceptions
	PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, //make the default fetch be an associative array
];
$pdo = new PDO($dsn, "admin", "password", $options);
function pubkey_to_pem($key)
{
	/* see https://github.com/Yubico/php-u2flib-server/blob/master/src/u2flib_server/U2F.php */
	if (strlen($key) !== 65 || $key[0] !== "\x04") {
		echo "KEY NOT VALID\n";
		return null;
	}
	/*
    * Convert the public key to binary DER format first
    * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
    *
    *  SEQUENCE(2 elem)                        30 59
    *   SEQUENCE(2 elem)                       30 13
    *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
    *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
    *   BIT STRING(520 bit)                    03 42 ..key..
    */
	$der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
	$der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
	$der .= "\x00" . $key;
	$pem  = "-----BEGIN PUBLIC KEY-----\x0A";
	$pem .= chunk_split(base64_encode($der), 64, "\x0A");
	$pem .= "-----END PUBLIC KEY-----\x0A";
	return $pem;
}
switch ($action) {
	default:
		?>
		<form action="/index.php?action=submit" method="post">
			Username:
			<input name="username" type="text" />
			<input name="register" type="submit" value="Register new user" />
			<input name="authenticate" type="submit" value="Authentcate user" />

		</form>
	<?php
	break;


	case "submit":
	if (isset($_POST["register"])) {
		$username = $_POST["username"];
		createCredentialsOnClient($username);
		echo "Created challenge for user: $username<br>";
	}
	if (isset($_POST["authenticate"])) {
		$username = $_POST["username"];
		echo "Authenticating: $username\n";
		authenticate($username);
	}
	break;


case "authenticate":
	$output = array();
	$appid = "mneerup.dk";
	$json = json_decode(file_get_contents("php://input"));

	$bs = base64_decode($json->response->authenticatorData);

	$ao = (object) array();

	$ao->rpIdHash = substr($bs, 0, 32);
	$ao->flags = ord(substr($bs, 32, 1));
	$ao->counter = substr($bs, 33, 4);

	$hashId = hash('sha256', $appid, TRUE);
	if ($hashId == $ao->rpIdHash) {
		$output[] = array("status"=> "hashes match");
	} else {
		$output[] = array("status"=> "wrong hash, something is wrong");
	}

	//decode
	$ao = (object) \CBOR\CBOREncoder::decode($attenstion);

	$clientdata = base64_decode($json->response->clientDataJSON);
	$authData = base64_decode($json->response->authenticatorData);
	$signature = base64_decode($json->response->signature);
	$cid = $json->id;
	$clientdatahash = hash('sha256', $clientdata, TRUE);

	$signeddata = $authData . $clientdatahash;
	$publicKey = pubkey_to_pem(base64url_decode(getPublicKey($cid)));


	if (openssl_verify($signeddata, $signature, $publicKey, OPENSSL_ALGO_SHA256)) {
		$output[] = array("authenticated" => "OK");
	} else {
		$output[] = array("authenticated" => "NOT OK");
	}

	echo json_encode($output);
	break;

case "saveCredentials":
	$username = $_SESSION["username"];
	$json = json_decode(file_get_contents("php://input"));
	$attenstion = array_to_string($json->response->attestationObject);

	//decode
	$ao = (object) \CBOR\CBOREncoder::decode($attenstion);

	$obj = base64_decode($json->response->clientDataJSON);
	$obj = json_decode($obj);
	$challenge_rsp = $obj->challenge;
	$challenge_utf8 =  $_SESSION["challenge"];

	$tmp = base64url_encode($challenge_utf8);

	if ($challenge_rsp == $tmp) {
		echo json_encode(array("status" => "OK"));
	} else {
		echo json_encode(array("status" => "NOT OK"));
		echo "$challenge_rsp == $tmp";
	}


	$bs = $ao->authData->get_byte_string();
	$ao = (object) array();
	$ao->attData = (object) array();
	$ao->attData->aaguid = substr($bs, 37, 16);
	$ao->attData->credIdLen = (ord($bs[53]) << 8) + ord($bs[54]);
	$credId = substr($bs, 55, $ao->attData->credIdLen);
	$cborPubKey  = substr($bs, 55 + $ao->attData->credIdLen); // after credId to end of string

	$ao->pubKey = \CBOR\CBOREncoder::decode($cborPubKey);

	/* assemblePublicKeyBytesData */
	$x = $ao->pubKey[-2]->get_byte_string();
	$y = $ao->pubKey[-3]->get_byte_string();
	$keyBytes = chr(4) . $x . $y;

	insert(base64url_encode($credId), base64url_encode($keyBytes), $username);
	break;
}



function authenticate($username)
{
	$challenge = generateRandomString(20);
	$_SESSION["challenge"]  = $challenge;



	$credentialId = getCredentialIds($username)[0]["credentialid"];
	$credentialId = base64_encode(base64url_decode($credentialId));
	?>

	<html>

	<body>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
		<script src="base64.js"></script>
		<script type="text/javascript">
			challenge = "<?= $challenge ?>";
			credentialId = "<?= $credentialId ?>";
			const publicKeyCredentialRequestOptions = {
				challenge: Uint8Array.from(
					challenge, c => c.charCodeAt(0)),
				allowCredentials: [{
					id: Uint8Array.from(
						atob(credentialId), c => c.charCodeAt(0)),
					type: 'public-key',
				}],
				timeout: 60000,
			}



			function bufferEncode(value) {
				return base64js.fromByteArray(value)
					.replace(/\+/g, "-")
					.replace(/\//g, "_")
					.replace(/=/g, "");
			}


			$(document).ready(function() {



				navigator.credentials.get({
					publicKey: publicKeyCredentialRequestOptions
				}).then(function(PublicKeyCredential) {
					console.log(PublicKeyCredential);


					console.log(PublicKeyCredential.response.authenticatorData);
					let authData = new Uint8Array(PublicKeyCredential.response.authenticatorData);
					let clientDataJSON = new Uint8Array(PublicKeyCredential.response.clientDataJSON);
					let rawId = new Uint8Array(PublicKeyCredential.rawId);
					let sig = new Uint8Array(PublicKeyCredential.response.signature);
					let userHandle = new Uint8Array(PublicKeyCredential.response.userHandle);



					$.ajax({
						url: '/index.php?action=authenticate',
						type: 'POST',
						data: JSON.stringify({
							id: PublicKeyCredential.id,
							rawId: bufferEncode(rawId),
							type: PublicKeyCredential.type,
							response: {
								authenticatorData: bufferEncode(authData),
								clientDataJSON: bufferEncode(clientDataJSON),
								signature: bufferEncode(sig),
								userHandle: bufferEncode(userHandle),
							},
						}),
						contentType: "application/json; charset=utf-8",
						dataType: "json",
					}).done(function(){
							$("body").append("User successfully authenticated (signature matches)");
					});


				});

			});
		</script>
	</body>

	</html>
<?php
}


// Create credentials on client and POST them to the server. The server will save the credentialID and public key
function createCredentialsOnClient($name)
{
	$challenge = generateRandomString(20);
	$_SESSION["challenge"]  = $challenge;
	$_SESSION["username"] = $name;

	?>

	<html>

	<body>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
		<script src="base64.js"></script>
		<script type="text/javascript">
			const chall = "<?= $challenge ?>";
			const publicKeyCredentialCreationOptions = {
				challenge: Uint8Array.from(
					chall, c => c.charCodeAt(0)),
				rp: {
					name: "my name",
					id: "mneerup.dk",
				},
				user: {
					id: Uint8Array.from(
						"okokok", c => c.charCodeAt(0)),
					name: "lee@webauthn.guide",
					displayName: "<?= $name ?> ",
				},
				pubKeyCredParams: [{
					alg: -7,
					type: "public-key"
				}],
				authenticatorSelection: {
					authenticatorAttachment: "cross-platform",
				},
				timeout: 60000,
				attestation: "direct"
			};

			function bufferEncode(value) {
				return base64js.fromByteArray(value)
					.replace(/\+/g, "-")
					.replace(/\//g, "_")
					.replace(/=/g, "");
			}
			$(document).ready(function() {

				navigator.credentials.create({
					publicKey: publicKeyCredentialCreationOptions
				}).then(function(newCredential) {
					console.log("PublicKeyCredential Created");
					console.log(newCredential);

					// Move data into Arrays incase it is super long
					let attestationObject = new Uint8Array(newCredential.response.attestationObject);
					let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
					let rawId = new Uint8Array(newCredential.rawId);



					var ao = [];
					(new Uint8Array(newCredential.response.attestationObject)).forEach(function(v) {
						ao.push(v);
					});

					$.ajax({
						url: '/index.php?action=saveCredentials',
						type: 'POST',
						data: JSON.stringify({
							id: newCredential.id,
							rawId: bufferEncode(rawId),
							type: newCredential.type,
							response: {
								attestationObject: ao,
								clientDataJSON: bufferEncode(clientDataJSON),
							},
						}),
						contentType: "application/json; charset=utf-8",
						dataType: "json",
					}).done(function(){
							$("body").append("User successfully created on server. Go to <a href='/index.php' >home</a> to verify you can login.");
					}).fail(function()  {
						    alert("Sorry. Server unavailable. ");
					}); 



				}).catch(function(err) {
					console.log(err);
					console.log(err.message);
				});
			});
		</script>
	</body>

	</html>




<?php
}


// helper functions


function insert($credentialid, $publickey, $username)
{
	global $pdo;
	$stmt = $pdo->prepare("INSERT INTO users (credentialid,publickey, username) VALUES (?,?,?)");
	$stmt->execute([$credentialid, $publickey, $username]);
}


function base64url_encode($data)
{
	// First of all you should encode $data to Base64 string
	$b64 = base64_encode($data);

	// Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
	if ($b64 === false) {
		return false;
	}

	// Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
	$url = strtr($b64, '+/', '-_');

	// Remove padding character from the end of line and return the Base64URL result
	return rtrim($url, '=');
}

function base64url_decode($data, $strict = false)
{
	// Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
	$b64 = strtr($data, '-_', '+/');

	// Decode Base64 string and return the original data
	return base64_decode($b64, $strict);
}

function array_to_string($a)
{
	$s = '';
	foreach ($a as $c) {
		$s .= chr($c);
	}
	return $s;
}



function generateRandomString($length = 10)
{
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++) {
		$randomString .= $characters[rand(0, $charactersLength - 1)];
	}
	return $randomString;
}



function getPublicKey($credentialId)
{
	global $pdo;
	$stmt = $pdo->prepare("SELECT * FROM users where credentialid = ?");
	$stmt->execute([$credentialId]);
	$row = $stmt->fetch();

	return $row["publickey"];
}



function getCredentialIds($username)
{
	global $pdo;
	$retval = array();
	$stmt = $pdo->prepare("SELECT * FROM users where username = ?");
	$stmt->execute([$username]);
	while ($row = $stmt->fetch()) {
		$retval[] = $row;
	}
	return $retval;
}


function string_to_array($s)
{
	/* convert binary string to array of uint8 */
	$a = [];
	for ($idx = 0; $idx < strlen($s); $idx++) {
		$a[] = ord($s[$idx]);
	}
	return $a;
}



?>
