<?php

class Storage_memcached {
    
    private $transenabled   = true;
    private $conn           = false;
    public $verbose         = true;
    private $ob             = "";
    private $transtarted    = false;
    private $CI = false;
    protected $use_mysql    = false; //use or not mysql means use hash_prefix table for mysql, we DO need mysql for the other tables.
    
    protected $use_memcached    = true;
    protected $memcached        = false;
    protected $cache_server     = array(
			'host'		=> '127.0.0.1',
			'port'		=> 11211,
			'weight'	=> 1
		);
    
    
    public $usinglists = array('googpub-phish-shavar','goog-malware-shavar', 'goog-unwanted-shavar');
    
    public function __construct($database=false,$username=false,$password=false,$host="localhost",$verbose=true) {
        
        $this->verbose = $verbose;
        
        $this->db_connect($database,$username,$password,$host);
               
        $this->use_memcached($this->use_memcached);
        
    }
    
    public function use_mysql($use) {
        $this->use_mysql = $use;
    }
    
    public function use_memcached($use) {
        $this->use_memcached = $use;
        if (!$this->memcached) {
            $this->memcached = new Memcached();   
            $this->memcached->addServer(
					$this->cache_server['host'],
					$this->cache_server['port'],
					$this->cache_server['weight']
				);
        } //else unload
    }
    
    /*Wrapper to connect to database. Simples.*/
    public function db_connect($database,$username,$password,$host="localhost") {
        $this->conn = mysqli_connect($host, $username, $password);
        if (!$this->conn) {
                $this->fatalerror('Could not connect: ' . mysqli_error($this->conn));
        }
        $this->outputmsg('Connected successfully to database server');
        $db_selected = mysqli_select_db($this->conn, $database);
        if (!$db_selected) {
                $this->fatalerror('Can\'t use $database : ' . mysqli_error($this->conn));
        }
        $this->outputmsg('Connected to database successfully');		
    }
    
    
    public function install() {
        
        mysqli_query($this->conn, "
CREATE TABLE IF NOT EXISTS `chunk` (
  `chunk_number` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `list_name` varchar(127) NOT NULL,
  `chunk_type` char(3) NOT NULL,
  PRIMARY KEY (`chunk_number`,`list_name`,`chunk_type`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
        
	mysqli_query($this->conn, "CREATE TABLE IF NOT EXISTS `full_hash` (
  `value` varbinary(32) NOT NULL,
  `list_name` varchar(127) NOT NULL,
  `downloaded_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`value`,`list_name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
        
	mysqli_query($this->conn, "CREATE TABLE IF NOT EXISTS `hash_prefix` (
  `value` varbinary(32) NOT NULL,
  `chunk_number` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `list_name` varchar(127) NOT NULL,
  `chunk_type` char(3) NOT NULL,
  `full_hash_expires_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`value`,`chunk_number`,`list_name`,`chunk_type`),
  KEY `chunk_number` (`chunk_number`,`list_name`,`chunk_type`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
        
    }
    
    public function trans_disable() {
        $this->transenabled = false;	
    }
                
    public function trans_enable() {
        $this->transenabled = true;
    }
                
    public function trans_begin() {
        if($this->transenabled) {
            $this->transtarted = true;
            $this->outputmsg("Begin MySQL Transaction");
            mysqli_query($this->conn, "BEGIN");
        }
    }
    
    public function close() {
        
        if ($this->use_memcached) {
            $this->memcached->quit();
        }
        
        mysqli_close($this->conn);	
        $this->outputmsg("Closing phpGSB. (Peak Memory: ".(round(memory_get_peak_usage()/1048576,3))."MB)");
    }
    
 
    public function trans_commit() {
        if($this->transtarted&&mysqli_ping($this->conn)&&$this->transenabled)
                {
                $this->transtarted = false;
                $this->outputmsg("Comitting Transaction");
                mysqli_query($this->conn, "COMMIT");
                }
    }
                
    public function trans_rollback() {
        if($this->transtarted&&mysqli_ping($this->conn)&&$this->transenabled)
                {
                $this->transtarted = false;
                $this->outputmsg("Rolling Back Transaction");
                mysqli_query($this->conn, "ROLLBACK");
                }
    }
    
    //UPDATER FUNCTIONS
    /*
     * Resets lists database, only called if GSB issues r:resetdatabase
     */
    public function reset_database() {
        //Lord knows why they would EVER issue this request!
        if(!empty($this->adminemail)) {
                mail($this->adminemail,'Reset Database Request Issued','For some crazy unknown reason GSB requested a database reset at '.time());
        }
        
        
        mysqli_query($this->conn, "TRUNCATE TABLE `full_hash`");
        mysqli_query($this->conn, "TRUNCATE TABLE `hash_prefix`");
        mysqli_query($this->conn, "DELETE FROM  `chunk` WHERE 1"); //Truncate doesn't work on a table referenced by foreign key
        
        if ($this->use_memcached ) {
            $this->memcached->flush();//This will delete phishtank urls, so load that again
            $keys = $this->memcached->getAllKeys(); //this never returns all keys...
            echo 'keys: '.count($keys)."\n";
        }
        
        $this->outputmsg('Databased reset.');
    }
  
 
    /*
     * Called when GSB returns a SUB-DEL or ADD-DEL response
     */
    function delete_range($range, $mode, $listname) {
        
        if(substr_count($range,'-')>0) {
            $deleterange = explode('-',trim($range));
            $clause = "`chunk_number` >= '{$deleterange[0]}' AND `chunk_number` <= '{$deleterange[1]}'";
        } else {
            $clause = "`chunk_number` = '$range'";
        }

        //Delete from hash_prefix table
        if ($this->use_memcached) {
            
            $query = "SELECT * FROM chunk WHERE ".$clause." AND list_name = '".$listname."' AND chunk_type = '".$mode."'";

            //Delete from chunk table
            $result = mysqli_query($this->conn, $query);
            if (!$result) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
            while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {

                $chnum = $row['chunk_number'];
                $hash_length = $row['prefix_type'];
//                $hashes = hex2bin($row['hashes']); //it is already a binary string
                $hashes = $row['hashes'];
                $n = strlen($hashes) / $hash_length;

                if ($n !== (int) $n) {
                    $this->outputmsg('Error! Wrong number of hashes or hash length! '.$listname.' '.var_export($chunk,true));
                }
                for($i = 0; $i < $n; $i = $i + $hash_length) {
                    
                    $hash_prefix = unpack("H*",substr($hashes, $i*$hash_length, $hash_length)); //unpack H* ?
                    $hash_prefix = $hash_prefix[1];

                    $key = $hash_prefix."-".$mode."-".$listname;
                    
                    $value = $this->memcached->get($key);
                    
                    if (!$value) {
                        $this->outputmsg('Something went wrong! missing key on memcached: '.$key);
                        continue;
                    }
                    if (!isset($value['chunk_numbers'][$chnum])) {
                        $this->outputmsg('Something went wrong! missing chunk number on key on memcached: '.$key);
                    } else {
                        unset($value['chunk_numbers'][$chnum]);
                    }
                    if (empty($value['chunk_numbers'])) {
                        $this->memcached->delete($key);
                    }
                    
                }
            }
                
        }
        
        
        $query = "DELETE FROM chunk WHERE ".$clause." AND list_name = '".$listname."' AND chunk_type = '".$mode."'";

        //Delete from chunk table
        if (!mysqli_query($this->conn, $query)) {
            $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
            return false;
        }
        
        if ($this->use_mysql) {
            $query = "DELETE FROM hash_prefix WHERE ".$clause." AND list_name = '".$listname."' AND chunk_type = '".$mode."'";
            if (!mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
        }

    }
    
    function chunk_exists($chunk,$listname) {

        $query = "SELECT COUNT(*) FROM chunk 
                WHERE chunk_number = '".$chunk->getChunkNumber()."' AND 
                chunk_type = '".($chunk->getChunkType() == 0?'add':'sub')."' AND list_name = '".$listname."' ";

        if (!$result = mysqli_query($this->conn, $query)) {
            $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
            return false;
        }

        $row=mysqli_fetch_array($result,MYSQLI_NUM);

        if ($row[0] > 0) {
            return true;
        }

        mysqli_free_result($result);

        return false;

    }
    
    /*
     * Delete expired hashes 
     */
    private function cleanup_expired_hashes() {

        mysqli_query($this->conn, "DELETE FROM full_hash WHERE expires_at < NOW() ");

    }
    
    function store_chunk($chunk, $listname) {
        
        if ($this->insert_chunk($chunk, $listname)) {
        
            $hash_length = ($chunk->getPrefixType() == \ChunkData\PrefixType::PREFIX_4B)? 4: 32;
            $hashes = $chunk->getHashes();

            $n = strlen($hashes) / $hash_length;

            if ($n !== (int) $n) {
                $this->outputmsg('Error! Wrong number of hashes or hash length! '.$listname.' '.var_export($chunk,true));
            }
            
            for($i = 0; $i < $n; $i++) {

                //insert hash_prefix              
                $hash_prefix = unpack("H*",substr($hashes, $i*$hash_length, $hash_length)); //unpack H* ?
                $hash_prefix = $hash_prefix[1];
//                $hash_prefix = bin2hex(substr($hashes, $i*$hash_length, $hash_length)); // bin2hex?? 4 bytes are 8 digits in Hexa

                if (!$this->insert_hash_prefix($chunk, $listname, $hash_prefix)) {
                    break;
                }
            }

            return true;
        }
        return false;
    }
    
    function insert_chunk($chunk, $listname) {
        
        //write it on disk
        if ($this->use_memcached) {
            
            $hash_length = ($chunk->getPrefixType() == \ChunkData\PrefixType::PREFIX_4B)? 4: 32;
            $hashes = bin2hex($chunk->getHashes());
            if ($hashes) {
                $hashes = '0x'.$hashes;
            } else {
                $hashes = 'NULL';
//                $this->outputmsg('Empty chunk: '.$chunk->getChunkNumber()."', '".($chunk->getChunkType() == 0?'add':'sub')."', '".$listname."', ".$hash_length);
            }
            $query = "INSERT INTO chunk (chunk_number, chunk_type, list_name, prefix_type, hashes)  
                    VALUES ( '".$chunk->getChunkNumber()."', '".($chunk->getChunkType() == 0?'add':'sub')."', '"
                    .$listname."', ".$hash_length.
                    ", ".$hashes." )";
        } else {
            $query = "INSERT INTO chunk (chunk_number, chunk_type, list_name)  
                    VALUES ( '".$chunk->getChunkNumber()."', '".($chunk->getChunkType() == 0?'add':'sub')."', '".$listname."' )";
        }
        
        if (!$result = mysqli_query($this->conn, $query)) {
            $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn). ' query: '.$query);
            die();
            return false;
        }
        
        return true;
    }
    
    function insert_hash_prefix($chunk, $listname, $hash) {
        
        if ($this->use_memcached) {
        
            $key = $hash."-".($chunk->getChunkType() == 0?'add':'sub')."-".$listname;
            
            $value = $this->memcached->get($key);
            $exist = true;
            if (!$value) {
                $value = array('chunk_numbers' => array());
                $exist = false;
                $value['chunk_numbers'][$chunk->getChunkNumber()] = true; //add the chunk number as key on the array
            } else {
                $value['chunk_numbers'][$chunk->getChunkNumber()] = true; //add the chunk number as key on the array
            }
            
            $this->memcached->set($key, $value, 0);
        }
        
        if ($this->use_mysql) {
            //full_hash_expires_at ?
            $query = "INSERT INTO hash_prefix (value, chunk_number, chunk_type, list_name) ".
                    " VALUES (  0x".$hash.", '".$chunk->getChunkNumber()."', '".($chunk->getChunkType() == 0?'add':'sub')."', '".$listname."')";

            if (!$result = mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
        }
        
        return true;
        
    }

    
    /*
     * Function to output messages, used instead of echo,
     * will make it easier to have a verbose switch in later
     * releases
     */
    function outputmsg($msg) {
       if($this->verbose) {
           ob_start();
           echo $msg.'...'."\n";
           $this->ob .= ob_get_contents();
           ob_end_flush();
       }
    }

    /*
     * Get ranges of existing chunks from a requested list
     * and type (add or sub return them and set
     * mainlist to recieved for that chunk (prevent dupes)
     */
    function get_ranges($listname,$chunk_type) {

        $query = " SELECT chunk_number FROM chunk "
                . " WHERE list_name = '".$listname."' AND chunk_type = '".$chunk_type."' "
                . " ORDER BY chunk_number ASC ";
        
        if (!$result = mysqli_query($this->conn, $query)) {
            $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
            return false;
        }

        $i = 0;
        $start = 0;
        $ranges = array();
        while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {
            $number = $row['chunk_number'];
            if($i==0) {
                $start = $number;
                $previous = $number;
            } else {
                $expected = $previous + 1;
                if($number != $expected) {
                    if($start == $previous)
                            $ranges[] = $start;
                    else
                            $ranges[] = $start.'-'.$previous;
                    $start = $number;
                }
                $previous = $number;
            }
            $i++;
        }
        
        if ( $start > 0 && $previous > 0 ) {
            if($start==$previous) {
                $ranges[] = $start;
            } else {
                $ranges[] = $start.'-'.$previous;
            }
        }
        return $ranges;
    }
        
    
    public function lookup_hash_prefix($hash_prefix) {
    
        $foundm = false;
        if ($this->use_memcached) {
            $foundm = $this->lookup_hash_prefix_memcached($hash_prefix);
        }
        
        $foundmy = $this->lookup_hash_prefix_mysql($hash_prefix);
        
        if (!$foundm && $foundmy) {
            $this->outputmsg('WARNING!!! Hash found on mysql but not on Memcached!!! ');
        }
        
        return $foundm? $foundm : $foundmy ;
    }
    
    public function lookup_hash_prefix_memcached($hash_prefix) {
        
        if ($this->use_memcached) {
            //build the keys
            foreach($this->usinglists as $listname) {
                $key = $hash_prefix."-add-".$listname;
                $entryadd = $this->memcached->get($key);
                
                if (!$entryadd) {
                    continue; //not on add list
                }
                $key = $hash_prefix."-'sub'-".$listname;
                $entrysub = $this->memcached->get($key);
            
                if ($entrysub) {
                    continue;  ///on add list and sub list
                }
                $this->outputmsg('Memcached. Prefix Hash found on list: '.$listname);
                return true; //on add list, and not on sub list
            }
            //not on any add list, or on add and sub lists
        }
        
        return false;
    }
    
    public function lookup_hash_prefix_mysql($hash_prefix) {
        
        if ($this->use_mysql) {
            $query = "SELECT list_name FROM hash_prefix WHERE chunk_type = 'add' AND value = 0x".$hash_prefix." "; //Hash prefix is 8 digits of sha1 which is hex value

            if (!$result = mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
            $list_add = array();
            while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {
                $list_add[] = $row['list_name'];
            }

            if (count($list_add) == 0) {
                return false; //not on add list
            }

            $query = "SELECT list_name FROM hash_prefix WHERE chunk_type = 'sub' AND value = 0x".$hash_prefix." "; //Hash prefix is 8 digits of sha1 which is hex value

            if (!$result = mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
            $list_sub = array();
            while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {
                $list_sub[] = $row['list_name'];
            }

            if (count($list_sub) == 0) {
                $this->outputmsg('Mysql. Prefix Hash found on lists: '.implode(',',$list_add));
                return true; //on add list, and not on sub list
            }

            if (array_diff($list_add, $list_sub)) { //if it is on any list as 'add', and not on the same list as 'sub'
                $this->outputmsg('Mysql. Prefix Hash found on lists: '.implode(',',array_diff($lists_add, $lists_sub)));
                return true;
            }
        }
        
        return false;
        
    }
    
    /*
     * Check if hashes for the given hash prefix have expired
     * and that prefix needs to be re-queried
     */
    public function full_hash_sync_required($hash_prefix) {
        
        if ($this->use_memcached) {
          
            foreach($this->usinglists as $listname) {
                
                $key = $hash_prefix."-add-".$listname;

                $value = $this->memcached->get($key);
                
                if (isset($value['full_hash_expires_at']) && $value['full_hash_expires_at'] > time()) {
                    return false;
                }
            }
            return true;
        }
        if ($this->use_mysql) {
            $query = "SELECT COUNT(*) as c 
                FROM hash_prefix WHERE 
               full_hash_expires_at > NOW() AND chunk_type = 'add' 
               AND value = 0x".$hash_prefix." "; 

            if (!$result = mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return true;
            }

            $row = mysqli_fetch_array($result, MYSQLI_ASSOC);

            return ($row['c'] == 0);
        }
    }

    public function store_full_hashes($hash_prefix, $hashes) {
        
        $this->cleanup_expired_hashes();
        
        $cache_lifetime = $hashes['cache_lifetime'];
        
        foreach($hashes['hashes'] as $list => $values) {
            foreach($values as $hash_value) {
                $query = "INSERT INTO full_hash (value, list_name, expires_at)
                    VALUES ( 0x".$hash_value.", '".$list."', (NOW() + INTERVAL ".$cache_lifetime." SECOND) )";
                if (!$result = mysqli_query($this->conn, $query)) {
                    $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
//                    return false;
                }
            }
        }
        
        //add hash prefix expiration time
        if ($this->use_memcached) {
            
            foreach($this->usinglists as $listname) {
            
                $key = $hash_prefix."-add-".$listname;

                $value = $this->memcached->get($key);
                
                $value['full_hash_expires_at'] = time() + $cache_lifetime;
                
                $this->memcached->set($key, $value, 0);
                
            }
            
        }
        if ($this->use_mysql) {
            $query = "UPDATE hash_prefix SET full_hash_expires_at = (NOW() + INTERVAL ".$cache_lifetime." SECOND)
                WHERE chunk_type = 'add' AND value = 0x".$hash_prefix;

            if (!$result = mysqli_query($this->conn, $query)) {
                $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
                return false;
            }
        }
        
    }
    
    /*
     * Query DB to see if hash is blacklisted
     */
    function lookup_full_hash($hash) {
        
        $query = 'SELECT list_name FROM full_hash WHERE value = 0x'.$hash;
        
        if (!$result = mysqli_query($this->conn, $query)) {
            $this->outputmsg(__FUNCTION__." Error: " . mysqli_error($this->conn));
            return false;
        }
        $lists = array();
        while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {
            $lists[] = $row['list_name'];
        }
        
        if (count($lists) > 0) {
            return $lists;
        }
        false;
        
    }

    
}
