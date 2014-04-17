<?php

class MutiPortScan
{
	var $connect_number = 0;
	var $connect_number_limit = 500;
	var $connect_timeout = 10000000;
	var $connect_usleep = 500000;
	
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
}

$a = new MutiPortScan();
$a->scan_port($argv[1], $argv[2], $argv[3], $argv[4]);
?>