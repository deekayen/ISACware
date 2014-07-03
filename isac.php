<?php

/**
 * IMail SMTP Access Control list maker
 *
 * This is shareware, so if you use this, and implement the
 * output file, please paypal some money to paypal@deekayen.net.
 * Just think how many hours it might have taken you to
 * engineer the output yourself and how nice it was to have
 * this already there to do it for you.
 *
 * @link http://support.ipswitch.com/kb/IM-20040413-DM01.htm
 * @author David Kent Norman <deekayen [-@-] deekayen {dot} net>
 * @copyright 2006 David Kent Norman
 * @version 2.0
 */

/**
 * Configuration
 */

/**
 * @var array $okean_files Array of files from http://www.okean.com/
 *                        in CIDR format
 */
$okean_files = array('sinokoreacidr.txt');

/**
 * @var array $blackholes_files Array of files from http://blackholes.us/
 *                              in rbldnsd format
 */
$blackholes_files = array('countries.rbl');

/**
 * @var array $default_access 1 for default grant, 0 for default deny
 */
$default_access = 1;

/**
 * End Configuration
 */

require_once('Net/IPv4.php');

$output = '93010000';  // Version Stamp - DWORD (4 bytes) Currently 403 (0x0193)
					   // bytes are in 2 bit blocks in reverse order
$output .= '01000000'; // Locked Flag - DWORD (4 bytes) Not used - Set to 1 (locked)
$output .= '0e000000'; // Lock ID - DWORD (4 bytes) Not used - Set to 14 (0x0E)
$output .= $default_access ? '01000000' : '00000000'; // Grant Flag
                                                      // DWORD (4 bytes) Set to 1 for default grant,
                                                      //                        0 for default deny


$size = 2;
$ips = '';

foreach($okean_files as $file_to_read) {
    $fp = @fopen($file_to_read, 'r');
    if(is_resource($fp)) {
        while(!feof($fp)) {
            $buffer = fgets($fp);
            if($buffer{0} != '#' && ($buffer{0} != '/' && $buffer{1} != '/')) {
                $cidr = preg_split("/[\s]+/", $buffer, -1);
                $net = Net_IPv4::parseAddress($cidr[0]);
                if($net) {
                    $ips .= Net_IPv4::atoh($net->ip);
                    $ips .= Net_IPv4::atoh($net->netmask);
                    $size += 2;
                }
            }
        }
        fclose($fp);
    } else {
        echo 'I could not open or read '. $file_to_read .' listed in the $okean_files
              configuration variable. Did you edit the configuration
              variables in isac.php? Did you spell the filename correctly? Does it exist?';
    }
}

foreach($blackholes_files as $file_to_read) {
    $fp = @fopen($file_to_read, 'r');
    $blackholes_line = 0;
    $blackholes_head = true;
    $blackholes_countries = array();
    $blackholes_ip_ok = false;
    if(is_resource($fp)) {
        while(!feof($fp)) {
            $buffer = rtrim(fgets($fp));
            $blackholes_line++;
            if(!empty($buffer) && $blackholes_line > 10) {
                //preg_match("/\n\$DATASET\sgeneric\s\w{2}\n@\sA\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\n@\sTXT\s\"\w+\"\n\n/")

                if($blackholes_head == true && preg_match("/^\\\$DATASET\sip4set\s(\w{2})$/", $buffer, $matches)) {
                    $buffer = fgets($fp);
                    $blackholes_countries[$matches[1]] = substr($buffer, strrpos($buffer, ':')+1);
                    fgets($fp); // skip generic
                    fgets($fp); // skip A
                    fgets($fp); // skip TXT
                    fgets($fp); // skip \n
                }
                elseif($blackholes_head == true && preg_match("/^\\\$DATASET\sip4set\s(\w{2})\s@$/", $buffer, $matches)) {
                    $blackholes_head == false;
                    if(!isset($_POST['blackholes_selected_countries'])) {
                      die(blackholes_country_selection($blackholes_countries));
                    }
                    if(in_array($matches[1], $_POST['blackholes_selected_countries'])) {
                        $blackholes_ip_ok = true;
                    }
                    else {
                        $blackholes_ip_ok = false;
                    }
                    fgets($fp); // skip :d.d.d.d:ww
                    fgets($fp); // skip d.d.d.d:d.d.d.d:w+
                }
                elseif($blackholes_ip_ok == true && preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}/", $buffer)) {
                    $net = Net_IPv4::parseAddress($buffer);
                    if($net) {
                        $ips .= Net_IPv4::atoh($net->ip);
                        $ips .= Net_IPv4::atoh($net->netmask);
                        $size += 2;
                    }
                }
            }
        }
        fclose($fp);
    } else {
        echo 'I could not open or read '. $file_to_read .' listed in the $blackholes_files
              configuration variable. Did you edit the configuration
              variables in isac.php? Did you spell the filename correctly? Does it exist?';
    }
}

$output .= dec2_4byte_hex($size, 2, 4);
$output .= $ips;
unset($ips);
$output .= '00000000';
$output .= 'FFFFFFFF';

$fp = fopen('smtpd32.acc', 'w');
fwrite($fp, hex2bin($output));
fclose($fp);

/**
 * Make 4 byte hexadecimal number, 8 bytes long
 *
 * @param int $int
 * @param int $group
 * @param int $size
 * @return string
 */
function dec2_4byte_hex($int, $group=2, $size=4)
{
    $ret = '';
    while($size--) {
       $n=($int>>($size*4)) & 0xf;
       $ret .= $n>9 ? chr(55 + $n) : $n;
    }
    $ret = $ret{2} . $ret{3} . $ret{0} . $ret{1} .'0000';
    return $ret;
}

/**
 * Hexidecimal to binary conversion
 * @param string $data
 * @return string
 */
function hex2bin($data)
{
    return pack("H" . strlen($data), $data);
}

/**
 * Print list of countries listed in the blackholes.us file to select for inclusion in smtpd32.acc
 *
 * @param array $blackholes_countries
 */
function blackholes_country_selection($blackholes_countries) { ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Country selection</title>
</head>

<body>
Select the countries to include in smtpd32.acc as blocked.
<form action="" method="post">

<?php
while(list($key, $value) = each($blackholes_countries)) {
  echo '<br /><input type="checkbox" name="blackholes_selected_countries[]" value="'. $key .'" checked="checked"/> '. $value;
}
?>
<br /><input type="submit" name="op" value="Submit countries" />
</form>
</body>
</html>
<?php

}

?>
