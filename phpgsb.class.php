<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.2.6
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2015, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.
*/

require_once 'Storage.class.php';
require_once "chunkdata/chunk.proto.php";

class phpGSB {

    //TODO make them private
    public $apikey          = "";
    public $usinglists = array('googpub-phish-shavar','goog-malware-shavar', 'goog-unwanted-shavar');

    private $version        = "0.3";
    private $realversion    = "0.3.0";
    private $apiversion	= "3.0";
    private $ob             = "";
    private $adminemail     = "";

    private $verbose	= true;


    public $pingfilepath = ""; //This is the path used to store the ping/last update files. (Must inc. trailing slash)
    //GENERIC FUNCTIONS (USED BY BOTH LOOKUP AND UPDATER)

    private $storage = false;

    /*
     * Automatically connect to database on calling class
     */
    public function __construct($database=false,$username=false,$password=false,$host="localhost",$verbose=false) {

        $this->verbose = $verbose;

        $this->outputmsg("phpGSB Loaded");

        if( $database && $username) {
            $this->storage = new Storage($database,$username,$password,$host, $verbose);
            $this->storage->verbose = $this->verbose;
        }

    }

    public function install() {
        $this->storage->install();
    }

    function silent() {
        $this->verbose = false;
        $this->storage->verbose = $this->verbose;
    }

    function verbose() {
        $this->verbose = true;
        $this->storage->verbose = $this->verbose;
    }

    /*
     * Function to output messages, used instead of echo,
     * will make it easier to have a verbose switch in later
     * releases
     */
    function outputmsg($msg) {
        if($this->verbose) {
            ob_start();
            if (is_array($msg)) {
                print_r($msg);
            } else {
                echo $msg;
            }
            echo '...'."\n\n\n";
            $this->ob .= ob_get_contents();
            ob_end_flush();
        }
    }

    /*
     * Function to output errors, used instead of echo,
     * will make it easier to have a verbose switch in later
     * releases
     */
    function fatalerror($msg) {
        if($this->verbose) {
            ob_start();
            print_r($msg);
            echo '...'."\n";
            $this->ob .= ob_get_contents();
            ob_end_flush();
        }
        $this->storage->trans_rollback();
        die();
    }

    /*
     * Simple logic function to calculate timeout
     * based on the number of previous errors
     */
    function calc($errors) {
        //According to Developer Guide Formula
        if($errors==1) {
                //According to Developer Guide (1st error, wait a minute)
                return 60;
        } elseif($errors>5) {
                //Check between 240 and 480 mins
                return (240 * 60) + rand(0, 14400);
        } else {
            //According to Developer Guide we simply double up our timeout each time and use formula:
            // a result between: 120min-240min for example
            return (30 * 60) + rand(0, 12600);
        }
    }

    /*
     * Writes backoff timeouts, uses calc() to calculate timeouts and then writes to file
     * for next check
     */
    function Backoff($errdata=false,$type = 'data') {
        if($type=="data") {
            $file = 'nextcheck.dat';
        } else {
            $file = 'nextcheck-'.$type.'.dat';
        }
        if (file_exists($this->pingfilepath.$file)) {
            $curstatus = explode('||',file_get_contents($this->pingfilepath.$file));
            $errors = $curstatus[1] + 1;
        } else {
            $errors = 1;
        }
        $seconds = $this->calc($errors);
        $until = time()+$seconds.'||'.$errors;
        file_put_contents($this->pingfilepath.$file,$until);
        $this->fatalerror(array("Invalid Response... Backing Off",$errdata));
    }

    /*
     * Writes timeout from valid requests to nextcheck file
     */
    function setTimeout($seconds, $type = 'data') {
        if($type=="data") {
                $file = 'nextcheck.dat';
        } else {
                $file = 'nextcheck-'.$type.'.dat';
        }

        if (file_exists($this->pingfilepath.$file)) {
                $curstatus = explode('||',file_get_contents($this->pingfilepath.$file));
//                $until = time()+$seconds.'||'.$curstatus[1];
                $until = time()+$seconds.'||0';
        } else {
                $until = time()+$seconds.'||';
        }
        file_put_contents($this->pingfilepath.$file,$until);
    }

    /*
     * Checks timeout in timeout files (usually performed at the start of script)
     */
    function checkTimeout($type) {
        if($type=="data") {
                $file = 'nextcheck.dat';
        } else {
                $file = 'nextcheck-'.$type.'.dat'; // 'full' for full hash  timeout
        }
        if (file_exists($this->pingfilepath.$file)) {
            $curstatus = explode('||',@file_get_contents($this->pingfilepath.$file));
            $time = $curstatus[0];
        } else {
            $time = 0; //allowed to requests
        }
        if( time() < $time) {
            $this->fatalerror("Must wait another ".($curstatus[0]-time()). " seconds before another request (".$type.") ");
        } else {
            $this->outputmsg("Allowed to request");
        }
    }
    /*
     * Function downloads from URL's, POST data can be passed via $options. $followbackoff indicates
     * whether to follow backoff procedures or not
     */
    function googleDownloader($url,$options,$followbackoff=false) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if(is_array($options)) {
                curl_setopt_array($ch, $options);
        };

        $data = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        if($followbackoff && $info['http_code']>299) {
            $this->Backoff($info,$followbackoff);
        }
        return array($info,$data);
    }

    /*
     * Process Chunks for V3 protocol
     */
    function processChunks($fulldata,$listname, $filepath) {

        $decoded_chunks = array();

//            file_put_contents($filepath, $fulldata);

        //read first 32 bits
        while (true) {

            $packed_size = substr($fulldata, 0, 4);
            $fulldata = substr($fulldata, 4); //remove first 4 chars

            if (strlen($packed_size) < 4) {
                break;
            }

            $size = unpack('N', $packed_size);
            $size = $size[1];

            $chunk = ChunkData::parseFromString(substr($fulldata, 0, $size));
            $fulldata = substr($fulldata, $size); //remove $size read characters

//                var_dump($chunk);

            if ($this->storage->chunk_exists($chunk, $listname)) {
                //echo 'Chunk '.$chunk->getChunkNumber().' '. $chunk->getChunkType().' '.$listname.' already exist in database. Skipping...'."\n";
                continue;
            }

            //add chunk
            $this->storage->store_chunk($chunk, $listname);

        }

    }

    /*
     * Get both add and sub ranges for a requested list
     */
    function getFullRanges($listname) {
        $addranges = $this->storage->get_ranges($listname,'add');
        $subranges = $this->storage->get_ranges($listname,'sub');
        return array("Subranges"=>$subranges,"Addranges"=>$addranges);
    }

    /*
     * Format a full request body for a desired list including
     * name and full ranges for add and sub
     */
    function formattedRequest($listname) {
        $fullranges = $this->getFullRanges($listname);
        $buildpart = '';
        if(count($fullranges['Subranges'])>0)
                $buildpart .= 's:'.implode(',',$fullranges['Subranges']);
        if(count($fullranges['Subranges'])>0&&count($fullranges['Addranges'])>0)
                $buildpart .= ':';
        if(count($fullranges['Addranges'])>0)
                $buildpart .= 'a:'.implode(',',$fullranges['Addranges']);
        return $listname.';'.$buildpart."\n";
    }


    /*
     * Main part of updater function, will call all other functions, merely requires
     * the request body, it will then process and save all data as well as checking
     * for ADD-DEL and SUB-DEL, runs silently so won't return anything on success
     */
    function getData($body) {
        if(empty($body)) {
                $this->fatalerror("Missing a body for data request");
        }
        $this->storage->trans_begin();
        $buildopts = array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body."\n");
        //Download list data
        $result = $this->googleDownloader("https://safebrowsing.google.com/safebrowsing/downloads?client=api&key=".$this->apikey."&appver=".$this->version."&pver=".$this->apiversion,$buildopts,"data");
        $this->outputmsg($result);
        preg_match('/^n:(.*)$/m', $result[1], $match); //# Minimum delay before polling again in seconds
        $timeout = $match[1];
        $this->setTimeout($timeout);
        if(substr_count($result[1],'r:pleasereset')>0) {
            $this->storage->reset_database();
        } else {
            $formattedlist = array();
            if(substr_count($result[1],'i:') > 0) {
                    $splitlists = explode('i:',$result[1]);
                    unset($splitlists[0]);
                    foreach($splitlists as $key=>$value) {
                        $listdata = explode("\n",trim($value));
                        $listname = $listdata[0];
                        unset($listdata[0]);
                        $formattedlist[$listname] = $listdata;
                    }
                    foreach($formattedlist as $key=>$value) {
                        $listname = $key;
                        foreach($value as $keyinner=>$valueinner) {
                            if(substr_count($valueinner,"u:")>0) {

                                $chunkdata = $this->googleDownloader('http://'.trim(str_replace('u:','',$valueinner)),false,"data");

                                //path in case you want to save the file into the disk, just for debug / testing
                                $path = ROOT_DIR.$key.'-'.$keyinner.'-'.substr($valueinner, strrpos($valueinner, '/')+1, 20);
                                $processed = $this->processChunks($chunkdata[1],$listname, $path);
                                $this->outputmsg("Saved a chunk file ");

                            } elseif(substr_count($valueinner,"ad:")>0) { //delete add chunks

                                if(substr_count($valueinner,',')>0) {
                                    $valueinner = explode(',',trim(str_replace("ad:","",$valueinner)));
                                    foreach($valueinner as $keyadd=>$valueadd) {
                                            $this->storage->delete_range($valueadd,'add',$listname);
                                    }
                                } else {
                                    $this->storage->delete_range(trim(str_replace("ad:","",$valueinner)),'add',$listname);
                                }

                            } elseif(substr_count($valueinner,"sd:")>0) {//delete sub chunks

                                if(substr_count($valueinner,',')>0) {
                                    $valueinner = explode(',',trim(str_replace("sd:","",$valueinner)));
                                    foreach($valueinner as $keyadd=>$valueadd) {
                                        $this->storage->delete_range($valueadd,'sub',$listname);
                                    }
                                } else {
                                    $this->storage->delete_range(trim(str_replace("sd:","",$valueinner)),'sub',$listname);
                                }

                            }
                        }
                    }
            } else {
                $this->outputmsg('No data available in list');
            }
        }
        $this->storage->trans_commit();
        return true;
    }

    /*
     * Shortcut to run updater
     * set $checktimeout to false to avoid backoff time checking and force the call
     */
    function run_update($force = false) {
        if (!$force) {
            $this->checkTimeout('data');
        }
        $require = "";
        foreach($this->usinglists as $value) {
            $require .= $this->formattedRequest($value);
        }
        $this->outputmsg("Using $require");
        $this->getData($require);
    }

    //LOOKUP FUNCTIONS
    /*Used to check the canonicalize function*/
    function validateMethod()
            {
            //Input => Expected
            $cases = array(
                                       "http://host/%25%32%35" => "http://host/%25",
                                       "http://host/%25%32%35%25%32%35" => "http://host/%25%25",
                                       "http://host/%2525252525252525" => "http://host/%25",
                                       "http://host/asdf%25%32%35asd" => "http://host/asdf%25asd",
                                       "http://host/%%%25%32%35asd%%" => "http://host/%25%25%25asd%25%25",
                                       "http://www.google.com/" => "http://www.google.com/",
                                       "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/" => "http://168.188.99.26/.secure/www.ebay.com/",
                                       "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/" => "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
                                       "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B" => 'http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+',
                                       "http://3279880203/blah" => "http://195.127.0.11/blah",
                                       "http://www.google.com/blah/.." => "http://www.google.com/",
                                       "www.google.com/" => "http://www.google.com/",
                                       "www.google.com" => "http://www.google.com/",
                                       "http://www.evil.com/blah#frag" => "http://www.evil.com/blah",
                                       "http://www.GOOgle.com/" => "http://www.google.com/",
                                       "http://www.google.com.../" => "http://www.google.com/",
                                       "http://www.google.com/foo\tbar\rbaz\n2" => "http://www.google.com/foobarbaz2",
                                       "http://www.google.com/q?" => "http://www.google.com/q?",
                                       "http://www.google.com/q?r?" => "http://www.google.com/q?r?",
                                       "http://www.google.com/q?r?s" => "http://www.google.com/q?r?s",
                                       "http://evil.com/foo#bar#baz" => "http://evil.com/foo",
                                       "http://evil.com/foo;" => "http://evil.com/foo;",
                                       "http://evil.com/foo?bar;" => "http://evil.com/foo?bar;",
                                       "http://\x01\x80.com/" => "http://%01%80.com/",
                                       "http://notrailingslash.com" => "http://notrailingslash.com/",
                                       "http://www.gotaport.com:1234/" => "http://www.gotaport.com:1234/",
                                       "  http://www.google.com/  " => "http://www.google.com/",
                                       "http:// leadingspace.com/" => "http://%20leadingspace.com/",
                                       "http://%20leadingspace.com/" => "http://%20leadingspace.com/",
                                       "%20leadingspace.com/" => "http://%20leadingspace.com/",
                                       "https://www.securesite.com/" => "https://www.securesite.com/",
                                       "http://host.com/ab%23cd" => "http://host.com/ab%23cd",
                                       "http://host.com//twoslashes?more//slashes" => "http://host.com/twoslashes?more//slashes"
                                       );
            foreach($cases as $key=>$value)
                    {
                    $canit = $this->Canonicalize($key);
                    $canit = $canit['GSBURL'];
                    if($canit==$value)
                            outputmsg("<span style='color:green'>PASSED: $key</span>");
                    else
                            outputmsg("<span style='color:red'>INVALID: <br>ORIGINAL: $key<br>EXPECTED: $value<br>RECIEVED: $canit<br> </span>");

                    }
            }
    /*
     * Special thanks Steven Levithan (stevenlevithan.com) for the ridiculously complicated regex
      required to parse urls. This is used over parse_url as it robustly provides access to
      port, userinfo etc and handles mangled urls very well.
      Expertly integrated into phpGSB by Sam Cleaver ;)
      Thanks to mikegillis677 for finding the seg. fault issue in the old function.
      Passed validateMethod() check on 17/01/12
     */
    function j_parseUrl($url)
            {
            $strict = '/^(?:([^:\/?#]+):)?(?:\/\/\/?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?(((?:\/(\w:))?((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/';
            $loose = '/^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/\/?)?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?)(((?:\/(\w:))?(\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/';
            preg_match($loose, $url, $match);
            if(empty($match))
                    {
                    //As odd as its sounds, we'll fall back to strict (as technically its more correct and so may salvage completely mangled urls)
                    unset($match);
                    preg_match($strict, $url, $match);
                    }
            $parts = array("source"=>'',"scheme"=>'',"authority"=>'',"userinfo"=>'',"user"=>'',"password"=>'',"host"=>'',"port"=>'',"relative"=>'',"path"=>'',"drive"=>'',"directory"=>'',"file"=>'',"query"=>'',"fragment"=>'');
              switch (count ($match)) {
                    case 15: $parts['fragment'] = $match[14];
                    case 14: $parts['query'] = $match[13];
                    case 13: $parts['file'] =  $match[12];
                    case 12: $parts['directory'] =  $match[11];
                    case 11: $parts['drive'] =  $match[10];
                    case 10: $parts['path'] =  $match[9];
                    case 9: $parts['relative'] =  $match[8];
                    case 8: $parts['port'] =  $match[7];
                    case 7: $parts['host'] =  $match[6];
                    case 6: $parts['password'] =  $match[5];
                    case 5: $parts['user'] =  $match[4];
                    case 4: $parts['userinfo'] =  $match[3];
                    case 3: $parts['authority'] =  $match[2];
                    case 2: $parts['scheme'] =  $match[1];
                    case 1: $parts['source'] =  $match[0];
              }
            return $parts;
            }
    /*Regex to check if its a numerical IP address*/
    function is_ip($ip)
            {
            return preg_match("/^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])" .
                            "(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/", $ip);
            }
    /*Checks if input is in hex format*/
    function is_hex($x)
            {
            //Relys on the fact that hex often includes letters meaning PHP will disregard the string
            if(($x+3) == 3)
                    return dechex(hexdec($x)) == $x;
            return false;
            }
    /*Checks if input is in octal format*/
    function is_octal($x)
            {
            //Relys on the fact that in IP addressing octals must begin with a 0 to denote octal
            return substr($x,0,1) == 0;
            }
    /*Converts hex or octal input into decimal */
    function hexoct2dec($value)
            {
            //As this deals with parts in IP's we can be more exclusive
            if(substr_count(substr($value,0,2),'0x')>0&&$this->is_hex($value))
                            {
                            return hexdec($value);
                            }
                    elseif($this->is_octal($value))
                            {
                            return octdec($value);
                            }
                    else
                            return false;
            }
    /*Converts IP address part in HEX to decimal*/
    function iphexdec($hex)
            {
            //Removes any leading 0x (used to denote hex) and then and leading 0's)
            $temp = str_replace('0x','',$hex);
            $temp = ltrim($temp,"0");
            return hexdec($temp);
            }
    /*Converts full IP address in HEX to decimal*/
    function hexIPtoIP($hex)
            {
            //Remove hex identifier and leading 0's (not significant)
            $tempip = str_replace('0x','',$hex);
            $tempip = ltrim($tempip,"0");
            //It might be hex
            if($this->is_hex($tempip))
                    {
                    //There may be a load of junk before the part we need
                    if(strlen($tempip)>8)
                            {
                            $tempip = substr($tempip,-8);
                            }
                    $hexplode = preg_split('//', $tempip, -1, PREG_SPLIT_NO_EMPTY);
                    while(count($hexplode)<8)
                            array_unshift($hexplode,0);
                    //Normalise
                    $newip = hexdec($hexplode[0].$hexplode[1]).'.'.hexdec($hexplode[2].$hexplode[3]).'.'.hexdec($hexplode[4].$hexplode[5]).'.'.hexdec($hexplode[6].$hexplode[7]);
                    //Now check if its an IP
                    if($this->is_ip($newip))
                            return $newip;
                    else
                            return false;
                    }
            else
                    return false;
            }
    /*Checks if an IP provided in either hex, octal or decimal is in fact
      an IP address. Normalises to a four part IP address.*/
    function isValid_IP($ip)
            {
            //First do a simple check, if it passes this no more needs to be done
            if($this->is_ip($ip))
                    return $ip;

            //Its a toughy... eerm perhaps its all in hex?
            $checkhex = $this->hexIPtoIP($ip);
            if($checkhex)
                    return $checkhex;

            //If we're still here it wasn't hex... maybe a DWORD format?
            $checkdword = $this->hexIPtoIP(dechex($ip));
            if($checkdword)
                    return $checkdword;

            //Nope... maybe in octal or a combination of standard, octal and hex?!
            $ipcomponents = explode('.',$ip);
            $ipcomponents[0] = $this->hexoct2dec($ipcomponents[0]);
            if(count($ipcomponents)==2)
                    {
                    //The writers of the RFC docs certainly didn't think about the clients! This could be a DWORD mixed with an IP part
                    if($ipcomponents[0]<=255&&is_int($ipcomponents[0])&&is_int($ipcomponents[1]))
                            {
                            $threeparts = dechex($ipcomponents[1]);
                            $hexplode = preg_split('//', $threeparts, -1, PREG_SPLIT_NO_EMPTY);
                            if(count($hexplode)>4)
                                    {
                                    $newip = $ipcomponents[0].'.'.$this->iphexdec($hexplode[0].$hexplode[1]).'.'.$this->iphexdec($hexplode[2].$hexplode[3]).'.'.$this->iphexdec($hexplode[4].$hexplode[5]);
                                    //Now check if its valid
                                    if($this->is_ip($newip))
                                            return $newip;
                                    }
                            }
                    }
            $ipcomponents[1] = $this->hexoct2dec($ipcomponents[1]);
            if(count($ipcomponents)==3)
                    {
                    //Guess what... it could also be a DWORD mixed with two IP parts!
                    if(($ipcomponents[0]<=255&&is_int($ipcomponents[0]))&&($ipcomponents[1]<=255&&is_int($ipcomponents[1]))&&is_int($ipcomponents[2]))
                            {
                            $twoparts = dechex($ipcomponents[2]);
                            $hexplode = preg_split('//', $twoparts, -1, PREG_SPLIT_NO_EMPTY);
                            if(count($hexplode)>3)
                                    {
                                    $newip = $ipcomponents[0].'.'.$ipcomponents[1].'.'.$this->iphexdec($hexplode[0].$hexplode[1]).'.'.$this->iphexdec($hexplode[2].$hexplode[3]);
                                    //Now check if its valid
                                    if($this->is_ip($newip))
                                            return $newip;
                                    }
                            }
                    }
            //If not it may be a combination of hex and octal
            if(count($ipcomponents)>=4)
              {
              $tmpcomponents = array($ipcomponents[2],$ipcomponents[3]);
              foreach($tmpcomponents as $key=>$value)
                      {
                      if(!$tmpcomponents[$key] = $this->hexoct2dec($value))
                              return false;
                      }

              array_unshift($tmpcomponents,$ipcomponents[0],$ipcomponents[1]);
              //Convert back to IP form
              $newip = implode('.',$tmpcomponents);

              //Now check if its valid
              if($this->is_ip($newip))
                      return $newip;
              }

            //Well its not an IP that we can recognise... theres only so much we can do!
            return false;
            }

    /*Had to write another layer as built in PHP urlencode() escapes all non
      alpha-numeric Google states to only urlencode if its below 32 or above
      or equal to 127 (some of those are non alpha-numeric and so urlencode
      on its own won't work).*/
    function flexURLEncode($url,$ignorehash=false)
            {
            //Had to write another layer as built in PHP urlencode() escapes all non alpha-numeric
            //google states to only urlencode if its below 32 or above or equal to 127 (some of those
            //are non alpha-numeric and so urlencode on its own won't work).
            $urlchars = preg_split('//', $url, -1, PREG_SPLIT_NO_EMPTY);
            if(count($urlchars)>0)
                    {
                    foreach($urlchars as $key=>$value)
                            {

                            $ascii = ord($value);
                            if($ascii<=32||$ascii>=127||($value=='#'&&!$ignorehash)||$value=='%')
                                    $urlchars[$key] = rawurlencode($value);
                            }
                    return implode('',$urlchars);
                    }
            else
                    return $url;
            }

    /*
     * Canonicalize a full URL according to Google's definition.
     */
    function Canonicalize($url) {
        //Remove line feeds, return carriages, tabs, vertical tabs
        $finalurl = trim(str_replace(array("\x09","\x0A","\x0D","\x0B"),'',$url));
        //URL Encode for easy extraction
        $finalurl = $this->flexURLEncode($finalurl,true);
        //Now extract hostname & path
        $parts = $this->j_parseUrl($finalurl);
        $hostname = $parts['host'];
        $path = $parts['path'];
        $query = $parts['query'];
        $lasthost = "";
        $lastpath = "";
        $lastquery = "";
        //Remove all hex coding (loops max of 50 times to stop craziness but should never
        //reach that)
        for ($i = 0; $i < 50; $i++) {
        $hostname = rawurldecode($hostname);
        $path = rawurldecode($path);
        $query = rawurldecode($query);
        if($hostname==$lasthost&&$path==$lastpath&&$query==$lastquery)
                break;
        $lasthost = $hostname;
        $lastpath = $path;
        $lastquery = $query;
        }
        //Deal with hostname first
        //Replace all leading and trailing dots
        $hostname = trim($hostname,'.');
        //Replace all consecutive dots with one dot
        $hostname = preg_replace("/\.{2,}/",".",$hostname);
        //Make it lowercase
        $hostname = strtolower($hostname);
        //See if its a valid IP
        $hostnameip = $this->isValid_IP($hostname);
        if($hostnameip)
                {
                $usingip = true;
                $usehost = $hostnameip;
                }
        else
                {
                $usingip = false;
                $usehost = $hostname;
                }
        //The developer guide has lowercasing and validating IP other way round but its more efficient to
        //have it this way
        //Now we move onto canonicalizing the path
        $pathparts = explode('/',$path);
        foreach($pathparts as $key=>$value)
                {
                if($value=="..")
                        {
                        if($key!=0)
                                {
                                unset($pathparts[$key-1]);
                                unset($pathparts[$key]);
                                }
                        else
                                unset($pathparts[$key]);
                        }
                elseif($value=="."||empty($value))
                        unset($pathparts[$key]);
                }
        if(substr($path,-1,1)=="/")
                $append = "/";
        else
                $append = false;
        $path = "/".implode("/",$pathparts);
        if($append&&substr($path,-1,1)!="/")
                $path .= $append;
        $usehost = $this->flexURLEncode($usehost);
        $path = $this->flexURLEncode($path);
        $query = $this->flexURLEncode($query);
        if(empty($parts['scheme']))
                $parts['scheme'] = 'http';
        $canurl = $parts['scheme'].'://';
        $realurl = $canurl;
        if(!empty($parts['userinfo']))
                $realurl .= $parts['userinfo'].'@';
        $canurl .= $usehost;
        $realurl .= $usehost;
        if(!empty($parts['port']))
                {
                $canurl .= ':'.$parts['port'];
                $realurl .= ':'.$parts['port'];
                }
        $canurl .= $path;
        $realurl .= $path;
        if(substr_count($finalurl,"?")>0)
                {
                $canurl .= '?'.$parts['query'];
                $realurl .= '?'.$parts['query'];
                }
        if(!empty($parts['fragment']))
                $realurl .= '#'.$parts['fragment'];
        return array("GSBURL"=>$canurl,"CleanURL"=>$realurl,"Parts"=>array("Host"=>$usehost,"Path"=>$path,"Query"=>$query,"IP"=>$usingip));
    }

    /*
     * SHA-256 input (short method).
     */
    function sha256($data) {
        return hash('sha256',$data);
    }

    /*
     * Make Hostkeys for use in a lookup
     */
    function makeHostKey($host,$usingip) {
        if($usingip) {
            $hosts = array($host."/");
        } else {
            $hostparts = explode(".",$host);
            if(count($hostparts)>2) {
                $backhostparts = array_reverse($hostparts);
                $threeparts = array_slice($backhostparts,0,3);
                $twoparts = array_slice($threeparts,0,2);
                $hosts = array(implode('.',array_reverse($threeparts))."/",implode('.',array_reverse($twoparts))."/");
            } else {
                $hosts = array($host."/");
            }
        }

        //Now make key & key prefix
        $returnhosts = array();
        foreach($hosts as $value) {
            $fullhash = $this->sha256($value);
            $returnhosts[$fullhash] = array(
                        "Host"=>$value,
                        "Prefix"=>substr($fullhash,0,8), // sha is Hex value. 8 digits are 4 bytes
                        "Hash"=>$fullhash
                    );
        }
        return $returnhosts;
    }

    /*
     * Hash up a list of values from makePrefixes() (will possibly be
     * combined into that function at a later date
     */
    function makeHashes($prefixarray) {
        if(count($prefixarray)>0) {
            $returnprefixes = array();
            foreach($prefixarray as $value) {
                $fullhash = $this->sha256($value);
                $returnprefixes[$fullhash] = array(
                    "Original"=>$value,
                    "Prefix"=>substr($fullhash,0,8), // sha is hex value. 8 digits are 4 bytes
                    "Hash"=>$fullhash);
            }
            return $returnprefixes;
        } else {
                return false;
        }
    }

    /*
     * Make URL prefixes for use after a hostkey check
     */
    function makePrefixes($host,$path,$query,$usingip) {
        $prefixes = array();
        //Exact hostname in the url
        $hostcombos = array();
        $hostcombos[] = $host;
        if(!$usingip) {
            $hostparts = explode('.',$host);
            $backhostparts = array_reverse($hostparts);
            if(count($backhostparts)>5)
                    $maxslice = 5;
            else
                    $maxslice = count($backhostparts);
            $topslice = array_slice($backhostparts,0,$maxslice);
            while($maxslice>1)
                    {
                    $hostcombos[] = implode('.',array_reverse($topslice));
                    $maxslice--;
                    $topslice = array_slice($backhostparts,0,$maxslice);
                    }
        } else {
            $hostcombos[] = $host;
        }
        $hostcombos = array_unique($hostcombos);
        $variations = array();
        if(!empty($path)) {
            $pathparts = explode("/",$path);
            if(count($pathparts)>4)
                                    $upperlimit = 4;
                            else
                                    $upperlimit = count($pathparts);
        }
        foreach($hostcombos as $key=>$value) {
            if(!empty($query))
                    $variations[] = $value.$path.'?'.$query;
            $variations[] = $value.$path;
            if(!empty($path))
                    {
                    $i = 0;
                    $pathiparts = "";
                    while($i<$upperlimit)
                            {
                            if($i!=count($pathparts)-1)
                                    $pathiparts = $pathiparts.$pathparts[$i]."/";
                            else
                                    $pathiparts = $pathiparts.$pathparts[$i];
                            $variations[] = $value.$pathiparts;
                            $i++;
                            }
                    }
        }
        $variations = array_unique($variations);
        return $this->makeHashes($variations);
    }

    /*
     * Does a full URL lookup on given lists, will check if its in database, if slight match there then
     * will do a full-hash lookup on GSB, returns (bool) true on match and (bool) false on negative.
     */
    function do_lookup($url) {
        $lists = $this->usinglists;
        //First canonicalize the URL
        $canurl = $this->Canonicalize($url);

        //Make hostkeys
        $hostkeys = $this->makeHostKey($canurl['Parts']['Host'],$canurl['Parts']['IP']);

        $prefixes = $this->makePrefixes($canurl['Parts']['Host'],$canurl['Parts']['Path'],$canurl['Parts']['Query'],$canurl['Parts']['IP']);

//        print_r($canurl);
//        print_r($hostkeys);
//        print_r($prefixes);

        //foreach hash
        foreach($prefixes as $keyinner => $valueinner) {

            $hash_prefix = $valueinner['Prefix'];


            if ($this->storage->lookup_hash_prefix($hash_prefix)) {

                $this->sync_full_hashes($hash_prefix);
                $lists = $this->storage->lookup_full_hash($valueinner['Hash']);
                if ($lists) {
                    return $lists;
                }
            }

        }

        return false;
    }

    /*
     * Sync full hashes starting with hash_prefix from remote server
     */
    function sync_full_hashes($hash_prefix) {

        if (!$this->storage->full_hash_sync_required($hash_prefix)) {
//            log.debug('Cached full hash entries are still valid for "0x%s", no sync required.', hash_prefix.encode("hex"))
            return;
        }

        $data = $this->get_full_hashes( $hash_prefix );

        $this->storage->store_full_hashes($hash_prefix, $data);

    }

    /*
     * Download and parse full-sized hash entries
     */
    function get_full_hashes($hash_prefix) {

        //FOLLOW backoff request frequency
        $this->checkTimeout('full_hash');

        $this->outputmsg('Downloading hashes for hash prefixes '.$hash_prefix);

//        $hash_prefix = pack('H*', $hash_prefix); //hash_prefix is Hexa, 8 digits, equivalent to 4 bytes.
        $hash_prefix = hex2bin($hash_prefix);
        $prefix_len = strlen($hash_prefix); //should be 4

//        die('prefix len: '.$prefix_len); //it is 4! :)

        $hashes_len = $prefix_len * 1; //only 1 hash prefix
        $header = $prefix_len.':'.$hashes_len;

        $body = $header."\n".$hash_prefix;

        //$this->outputmsg('Full hash request: '.$header."\n".$hash_prefix);

        $buildopts = array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body);
        //Download list data
        $result = $this->googleDownloader("https://safebrowsing.google.com/safebrowsing/gethash?client=api&key=".$this->apikey."&appver=".$this->version."&pver=".$this->apiversion,$buildopts,"full_hash");

        $split = explode("\n",$result[1],2);

        $cache_lifetime = (int) trim($split[0]);

        //Parse full-sized hash entry
        $hash_entry = $split[1];
        $hashes = array();
        $metadata = array();

        while(strlen($hash_entry)>0) {

            $has_metadata = false;

            $head_rest = explode("\n",$hash_entry,2);
            $hash_entry = $head_rest[1];
            $head = explode(':',$head_rest[0]); //head
            if (count($head) == 4) {
                if ($head[3] == 'm') {
                    $has_metadata = true;
                } else {
                    $this->outputmsg('Failed to parse full hash entry header: '.$head_rest[0]);
                    die('Died due error.');
                }
            }
            $list_name = $head[0];
            $entry_len = (int)$head[1];
            $entry_count = (int)$head[2];
            $hash_strings = array();
            $metadata_strings = array();
            for($i = 0; $i < $entry_count; $i++) {
                $hash_strings[] = bin2hex(substr($hash_entry, $i*$entry_len, $entry_len));
            }
            $hash_entry = substr($hash_entry, $entry_count*$entry_len); //remove hashs, leave metadata and the rest
            if ($has_metadata) {
                for($i = 0; $i < $entry_count; $i++) {
                    $metadata_split = explode("\n", $hash_entry, 2);
                    $next_metadata_len = (int) $metadata_split[0];
                    $hash_entry = $metadata_split[1];
                    $metadata_str = substr($hash_entry, 0, $next_metadata_len);
                    $metadata_strings[] = $metadata_str;
                    $hash_entry = substr($hash_entry, $next_metadata_len);
                }
            } elseif (strlen($hash_entry > 0)) {
                $this->outputmsg('Hash length does not match header declaration (no metadata) '.$result[1]);
            }
            $hashes[$list_name] = $hash_strings;
            $metadata[$list_name] = $metadata_strings;
        }
        return array(
                    'cache_lifetime' => $cache_lifetime,
                    'hashes' => $hashes,
                    'metadata' => $metadata,
                );
    }


    public function reset() {
        $this->storage->reset_database();
    }

    public function close() {
        $this->storage->close();
    }
}
