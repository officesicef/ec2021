<?php 
 
$i = 0;
 
function get_threat_metadefender($ip_or_domain)
{
	global $i;
	$ch = curl_init();
 
	if(filter_var($ip_or_domain, FILTER_VALIDATE_IP) !== false) {
		$url = 'https://api.metadefender.com/v4/ip/'.$ip_or_domain;
} else {
    $url = 'https://api.metadefender.com/v4/domain/'.$ip_or_domain;
}
 
        // set url
 
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'apikey: 58e49bcf7a89cd4a960d706ee4015b36',
));
        curl_setopt($ch, CURLOPT_URL, $url);
 
        //return the transfer as a string
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 
        // $output contains the output string
        $output = curl_exec($ch);
        $dekodiran = json_decode($output);
        echo "Metadefender detected by:".$dekodiran->lookup_results->detected_by."\n";
 
        if($dekodiran->lookup_results->detected_by > 0)
        		{
        			$i + 2;
        		}
 
        // close curl resource to free up system resources
        curl_close($ch);     
}
 
function get_threat_abuseipdb($ip_or_domain)
{
	global $i;
 
	if(filter_var($ip_or_domain, FILTER_VALIDATE_IP) !== false) {
		$cmd = ' curl -s -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress='.$ip_or_domain.'" -d maxAgeInDays=90 -d verbose -H "Key: e8681e21ea36a0b0454ccc354ff8306043c41c4c69409b6b32be3444bfa5f65e8ca72d407ec8dc77" -H "Accept: application/json"';
} else {
    return "SAMO IP";
}
 
$json = exec($cmd);
$dekodiran = json_decode($json);
echo 'AbuseDBScore:'.$dekodiran->data->abuseConfidenceScore."\n";
 
			if($dekodiran->data->abuseConfidenceScore > 0)
        		{
        			$i + 2;
        		}
 
}
 
 
function get_threat_pulsedive($ip_or_domain)
{
	global $i;
	$ch = curl_init();
 
	if(filter_var($ip_or_domain, FILTER_VALIDATE_IP) !== false) {
		$url = 'https://pulsedive.com/api/info.php?indicator='.$ip_or_domain;
} else {
    $url = 'https://pulsedive.com/api/info.php?indicator='.$ip_or_domain;
}
 
        // set url
 
        curl_setopt($ch, CURLOPT_URL, $url);
 
        //return the transfer as a string
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 
        // $output contains the output string
        $output = curl_exec($ch);
        $dekodiran = json_decode($output);
 
        if($dekodiran->error = "Indicator not found.")
        	{
        		echo "Pulsedive: nije nadjen\n";
        	}
        	else
        	{
        		echo "Pulsedive risk:".$dekodiran->risk."\n";
        		if($dekodiran->risk > 0)
        		{
        			$i + 2;
        		}
        	}
 
 
        // close curl resource to free up system resources
        curl_close($ch);     
}
 
function get_threat_xforce_ibmcloud($ip_or_domain)
{
	global $i;
 
	$ch = curl_init();
 
	if(filter_var($ip_or_domain, FILTER_VALIDATE_IP) !== false) {
		$url = 'https://exchange.xforce.ibmcloud.com/api/ipr/'.$ip_or_domain;
} else {
    $url = 'https://exchange.xforce.ibmcloud.com/api/url/'.$ip_or_domain;
}
 
 
curl_setopt($ch, CURLOPT_URL, $url);
 
        //return the transfer as a string
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Authorization: Basic ' . base64_encode("51964a17-86b2-4369-b2bf-ef1e8eb6be32" . ':' . "7a0617fe-8368-4ee3-afe7-7726147e8a96"),
));
 
        // $output contains the output string
        $output = curl_exec($ch);
        $dekodiran = json_decode($output);
 
        if(isset($dekodiran->error))
        	{
        		echo "xforce: error neki\n";
        	}
        	else
        	{
        		echo "Xforce score:".$dekodiran->score."\n";
 
        		if($dekodiran->score > 2.0)
        		{
        			$i = $i + 2;
        		}
        	}
 
        	curl_close($ch);
 
}
 
 
function get_threat_apivoid($ip_or_domain)
{
	global $i;
 
	$ch = curl_init();
 
    $url = 'https://endpoint.apivoid.com/threatlog/v1/pay-as-you-go/?key=d0d587de5a3b1f8e5484f5b3518ac419bd642db0&host='.$ip_or_domain;
 
 
 
curl_setopt($ch, CURLOPT_URL, $url);
 
        //return the transfer as a string
        @curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 
        // $output contains the output string
        $output = curl_exec($ch);
        $dekodiran = json_decode($output);
 
        if($dekodiran->credits_remained <= 5.0)
        	{
        		echo "Apivoid: ostalo ti manje od 5 kreditsa \n";
        	}
        	else
        	{
        		if($dekodiran->threatlog->detected == false)
        		{
        			echo "Apivoid threat detected: 0".$dekodiran->threatlog->detected."\n";
        			$i = $i + 0;
        		}
        		else
        		{
        			echo "Apivoid threat detected: 1"."\n";
        			$i = $i + 1;
        		}
 
        	}
 
        	curl_close($ch);
 
}
 
 
 ?>
<center>
 <form action="" method="POST">
  <label for="IP_ILI_DOMENA">IP ili DOMENA:</label><br>
  <input type="text" name="IP_ILI_DOMENA" id="IP_ILI_DOMENA" value="upisinesto"><br><br>
  <input type="submit" value="Submit">
</form>
<?php  if(isset($_POST['IP_ILI_DOMENA'])) : ?>
<ul>
	<li><?php get_threat_metadefender($_POST['IP_ILI_DOMENA']); ?></li>
	<li><?php get_threat_xforce_ibmcloud($_POST['IP_ILI_DOMENA']); ?></li>
	<li><?php get_threat_abuseipdb($_POST['IP_ILI_DOMENA']); ?></li>
	<li><?php get_threat_pulsedive($_POST['IP_ILI_DOMENA']); ?></li>
	<li><?php get_threat_apivoid($_POST['IP_ILI_DOMENA']); ?></li>
</ul>
<?php endif; ?>
 
<?php if($i > 0) : ?>
<h1 style="color:red">Ukupan threat score: <?php echo $i ?></h1>
<?php else : ?>
<h1 style="color:green">Ukupan threat score: <?php echo $i ?></h1>
<?php endif; ?>
</center>