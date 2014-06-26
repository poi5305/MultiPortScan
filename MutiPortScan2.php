<?php

class MutiPortScan
{
	var $connect_number = 0;
	var $connect_number_limit = 500;
	var $connect_timeout = 2000000;
	var $connect_usleep = 400000;
	
	var $socket_ip = "0.0.0.0";
	var $socket_retry = 0;
	var $connected_socket_array = array();
	var $done_socket_array = array();
	
	function MutiPortScan ()
	{
		return;
		
		$host = "140.113.15.84";
	    $port = "81";
	    $timeout = 15;  //timeout in seconds
		
	    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)
	      or die("Unable to create socket\n");
	
	    //socket_set_nonblock($socket)
	      //or die("Unable to set nonblock on socket\n");
	      
	    socket_connect($socket, $host, $port);
	    
	    $socket2 = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)
	      or die("Unable to create socket\n");
	
	    socket_set_nonblock($socket2)
	      or die("Unable to set nonblock on socket\n");
	      
	    socket_connect($socket2, $host, $port);
	    //socket_connect($socket, $host, 8);
		//ok 56
		
		return;
	    $time = time();
	    while (!@socket_connect($socket, $host, $port))
	    {
	      $err = socket_last_error($socket);
	      if ($err == 36 || $err == 37)
	      {
	        if ((time() - $time) >= $timeout)
	        {
	          socket_close($socket);
	          die("Connection timed out.\n");
	        }
	        sleep(1);
	        continue;
	      }
	      echo $err."\t";
	      die(socket_strerror($err) . "\n");
	    }
	    $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname("icmp"))
	      or die("Unable to create socket\n");
	    $package = "\x08\x00\x7d\x4b\x00\x00\x00\x00PingHost";
	    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 2, 'usec' => 0));
	    
	    socket_connect($socket, "140.113.15.2", null);
	    $ts = microtime(true);
	    socket_send($socket, $package, strlen($package), 0);
	    
		if (socket_read($socket, 255))
	   		$result = microtime(true) - $ts;
        else
        	$result = false;
        socket_close($socket);
        echo $result;
	}
	function scan_port($ip, $port_start, $port_end, $limit=1000)
	{
		$this->connect_number_limit = $limit;
		$this->socket_ip = $ip;
		$port = $port_start;
		while($port != $port_end+1)
		{
			if($this->connect_number >= $this->connect_number_limit)
			{
				usleep($this->connect_usleep);
				$this->reflash_connect();
				continue;
			}
			$this->connected_socket_array[$port] = array(
				"socket" => $this->create_tcp_connect($ip, $port)
				,"wait_count" => 0
				,"state" => 0
				,"retry" => 0
			);
			if($port % 1000 == 0)
			{
				echo "scanning to port: ~ $port\n";
				if(count($this->done_socket_array) != 0)
					print_r($this->done_socket_array);
			}
			//usleep(1000);
			$this->connect_number++;
			$port++;
		}
		$this->wait_connected();
	}
	function wait_connected()
	{
		while($this->connect_number != 0)
		{
			usleep($this->connect_usleep);
			$this->reflash_connect();
		}
		print_r($this->done_socket_array);
	}
	function reflash_connect()
	{
		$success_port = array();
		foreach($this->connected_socket_array as $port => &$socket)
		{
			$state = $this->test_tcp_connect( $socket["socket"], $this->socket_ip, $port);
			//echo "port". $port . " " . $state." ".$socket["wait_count"]."\n";
			if($state == 1 || $state == 3)
			{
				$socket["wait_count"] ++;
				if($state == 3 || $socket["wait_count"]*$this->connect_usleep >= $this->connect_timeout)
				{
					if($state == 3 && $socket["retry"] < $this->socket_retry)
					{
						//retry
						$socket["retry"] = 1;
						$socket["wait_count"] = 0;
						socket_close($socket["socket"]);
						$socket["socket"] = $this->create_tcp_connect($this->socket_ip, $port);
					}
					else
					{
						$socket["state"] = 3; // timeout
						$success_port[$port] = false;
					}
					
				}
				else
				{
					$socket["state"] = 1; // still wait
				}
			}
			elseif($state == 2)
			{
				$socket["state"] = 2;//success
				$success_port[$port] = true;
			}
		}
		foreach($success_port as $port => $value)
		{
			if($value)
			{
				//success
				$this->done_socket_array[$port] = true;
			}
			socket_set_block($this->connected_socket_array[$port]["socket"]);
			socket_close($this->connected_socket_array[$port]["socket"]);
			$this->connect_number--;
			unset($this->connected_socket_array[$port]);
		}
	}
	function create_tcp_connect($ip, $port)
	{
		$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die("Unable to create socket\n");
		socket_set_nonblock($socket);
		@socket_connect($socket, $ip, $port);
		return $socket;
	}
	function test_tcp_connect($socket, $ip, $port)
	{
		@socket_connect($socket, $ip, $port);
		$err = socket_last_error($socket);
		if ($err == 36 || $err == 37 || $err == 114 || $err == 115)
		{
			return 1;//waiting
		}
		elseif($err == 56 || $err == 106)
		{
			return 2;//connect success
		}
		elseif($err == 61 || $err == 111)
		{
			return 3;//failure
		}
		else
		{
			echo $err ." ".socket_strerror($err) . "\n";
			return 0;
		}
	}
	
	function scan_ping($ip_prefix, $ip_start, $ip_end, $limit=1000)
	{
		
		$this->connect_number_limit = $limit;
		$this->socket_ip = $ip_prefix;
		
		$ip = $ip_start;
		while($ip != $ip_end+1)
		{
			if($this->connect_number >= $this->connect_number_limit)
			{
				usleep($this->connect_usleep);
				$this->reflash_icmp_connect();
				continue;
			}
			$this->connected_socket_array[$ip] = array(
				"socket" => $this->create_icmp_connect($ip)
				,"wait_count" => 0
				,"state" => 0
				,"retry" => 0
			);
			if($ip % 20 == 0)
			{
				echo "scanning to port: ~ $ip\n";
				//if(count($this->done_socket_array) != 0)
				//	print_r($this->done_socket_array);
			}
			//usleep(1000);
			$this->connect_number++;
			$ip++;
		}
		$this->wait_icmp_connected();
	}
	function create_icmp_connect($ip)
	{		
		$socket = socket_create(AF_INET, SOCK_RAW, getprotobyname("icmp")) or die("Unable to create socket\n");
		socket_set_nonblock($socket);
		socket_connect($socket, "{$this->socket_ip}.$ip", null);

		$package = "\x08\x00\x7d\x4b\x00\x00\x00\x00PingHost";
		socket_send($socket, $package, strlen($package), 0);
		   		
		return $socket;
	}
	function reflash_icmp_connect()
	{
		$success_port = array();
		foreach($this->connected_socket_array as $ip => &$socket)
		{
			$state = $this->test_icmp_connect( $socket["socket"]);
			//echo "port". $ip . " " . $state." ".$socket["wait_count"]."\n";
			if($state == 1 || $state == 3)
			{
				$socket["wait_count"] ++;
				if($state == 3 || $socket["wait_count"]*$this->connect_usleep >= $this->connect_timeout)
				{
					if($state == 3 && $socket["retry"] < $this->socket_retry)
					{
						//retry
						$socket["retry"] = 1;
						$socket["wait_count"] = 0;
						socket_close($socket["socket"]);
						$socket["socket"] = $this->create_icmp_connect($ip);
					}
					else
					{
						$socket["state"] = 3; // timeout
						$success_port[$ip] = false;
					}
				}
				else
				{
					$socket["state"] = 1; // still wait
				}
			}
			elseif($state == 2)
			{
				$socket["state"] = 2;//success
				$success_port[$ip] = true;
			}
		}
		foreach($success_port as $ip => $value)
		{
			
			if($value)
			{
				//success
				$this->done_socket_array[$ip] = true;
			}
			else
			{
				$this->done_socket_array[$ip] = false;
			}
			socket_set_block($this->connected_socket_array[$ip]["socket"]);
			socket_close($this->connected_socket_array[$ip]["socket"]);
			$this->connect_number--;
			unset($this->connected_socket_array[$ip]);
		}
	}
	function test_icmp_connect($socket)
	{
		if (socket_read($socket, 255))
			return 2;
        else
        	return 1;
	}
	function wait_icmp_connected()
	{
		while($this->connect_number != 0)
		{
			usleep($this->connect_usleep);
			$this->reflash_icmp_connect();
		}
		ksort($this->done_socket_array);
		foreach($this->done_socket_array as $ip => $v)
		{
			if($v)
				echo "{$this->socket_ip}.$ip ===PING:SUCCESS===\n";
			else
				echo "{$this->socket_ip}.$ip ---PING:Failure\n";
			
		}
	}
}

$a = new MutiPortScan();
if($argc < 6)
{
	die("usage: ./thisfile ping|port ip range_start range_end socket_number\n ");
}
$type = "scan_".$argv[1];
$a->$type ($argv[2], $argv[3], $argv[4], $argv[5]);
?>
