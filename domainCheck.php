<?php 
include("classes/whois/server_list.php");
include("classes/whois/whois_class.php");

$_POST = json_decode(file_get_contents('php://input'), true);
// $domain = $_POST['domain'];
// $tld = $_POST['tld'];

$domain = 'noldor222';
$tld = 'co.za';

$my_whois = new Whois_domain;
$my_whois->possible_tlds = array_keys($servers);
$my_whois->tld = $tld;
$my_whois->domain = $domain;
$my_whois->free_string = $servers[$tld]['free'];
$my_whois->whois_server = $servers[$tld]['address'];
$my_whois->whois_param = $servers[$tld]['param'];
$my_whois->full_info = 'no';
$my_whois->process();

$checkMessage = $my_whois->msg;

#print $checkMessage;

header('Content-type: application/json');
$return = array('status' => 'not available','domain'=> $domain, 'tld'=> $tld);
#$return = array('status' => 'not available');

if (strpos($checkMessage, 'free') !== false)
{
    $return['status'] = 'free';
}

print json_encode($return);

?>