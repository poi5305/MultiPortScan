<?php

class MultiPortScan
{
	private $connect_number = 0;
	private $connect_number_limit = 500;
	private $connect_timeout = 2000000;
	private $connect_usleep = 400000;
	
	private $socket_ip = "0.0.0.0";
	private $socket_retry = 0;
	private $connected_socket_array = array();
	private $done_socket_array = array();
	private $supported_protocols = [ 'icmp' , 'tcp' ];
	public function __construct()
	{
		return;
    }
	
	public function scan_port($ip, $port_start, $port_end, $limit=1000)
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
	private function wait_connected()
	{
		while($this->connect_number != 0)
		{
			usleep($this->connect_usleep);
			$this->reflash_connect();
		}
		print_r($this->done_socket_array);
	}
	public function create_tcp_connect($ip, $port)
	{
		return $this->create_connection("tcp",$ip,$port);
	}
	public function test_tcp_connect($socket, $ip, $port)
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
	
	public function scan_ping($ip_prefix, $ip_start, $ip_end, $limit=1000)
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
	public function create_icmp_connect($ip)
	{		
		return $this->create_connection( "icmp", $ip, null, "\x08\x00\x7d\x4b\x00\x00\x00\x00PingHost" );
	}
	public function create_connection( $proto, $ip, $port = null, $send_payload_now=null )
	{
		if( ! $this->proto_is_supported($proto) )
		{
			echo "Protocol $proto not supported [create_connection]\n";
			return -1;
		}
		$payload=$sock_type="";
		switch( $proto )
		{
			case "tcp": 
				$sock_type = SOCK_STREAM;
				$payload="";
				break;
			case "icmp":
				$sock_type = SOCK_RAW;
				break;
			default:
				echo "Unknown protocol passed: $proto [create_connection]\n";
				return -2;
		}

		echo $sock_type . " " . getprotobyname($proto) . " " . $proto . "\n";
		$socket = socket_create(AF_INET, $sock_type , getprotobyname($proto)) or die("Unable to create socket\n");
		socket_set_nonblock($socket);
		// Not sure why this is appending an ip to an ip
		// socket_connect($socket, "{$this->socket_ip}.$ip", $port);
		socket_connect($socket,$ip,$port);
		if( $send_payload_now )
		{
			socket_send($socket, $send_payload_now, strlen($send_payload_now), 0);
		}
		   		
		return $socket;
		
	}
	private function reflash_icmp_connect()
	{
		return $this->reflash("icmp");
	}
	private function reflash_connect()
	{
		return $this->reflash("tcp");
	}
	public function proto_is_supported($proto)
	{
		return in_array($proto,$this->supported_protocols);
	}
	private function reflash($proto)
	{
		if( ! $this->proto_is_supported($proto) )
		{
			echo "Protocol $proto not supported [reflash]\n";
			return -1;
		}
		$testFunc = "test_${proto}_connect";
		$createFunc = "create_${proto}_connect";
		$success_port = array();
		foreach($this->connected_socket_array as $ip => &$socket)
		{
			$state = $this->$testFunc( $socket["socket"], $this->socket_ip, $ip );
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
						$socket["socket"] = $this->$createFunc($ip);
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
			$this->done_socket_array[$ip] = (bool)$value;
			socket_set_block($this->connected_socket_array[$ip]["socket"]);
			socket_close($this->connected_socket_array[$ip]["socket"]);
			$this->connect_number--;
			unset($this->connected_socket_array[$ip]);
		}
	}
	public function test_icmp_connect($socket,$ignored=null,$ignored2=null)
	{
		if (socket_read($socket, 255))
			return 2;
        else
        	return 1;
	}
	private function wait_icmp_connected()
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

function usage() 
{
    $a = <<<EOF
MultiPortScan Version 3.0
=========================
Original Author: Andy - poi5305@gmail.com - https://github.com/poi5305
Other Author: William Merfalen - wmerfalen@gmail.com - https://github.com/iteratedlateralus

usage: ./thisfile ping|port ip range_start range_end socket_number

EXAMPLES:
	# Perform an ICMP network scan for hosts 192.168.0.1-25
	./thisfile ping 192.168.0 1 25 0		#Note: 192.168.0 is not a typo

	# Perform a TCP scan of ports 1 through 500 on localhost
	./thisfile port 127.0.0.1 1 500 8

NOTE: In order to use ICMP scan, you must run the script as r00t since we are opening a raw socket

EOF;
	return $a;
}

$a = new MultiPortScan();
if($argc < 6)
{
	die(usage());
}
$type = "scan_".$argv[1];
$a->$type ($argv[2], $argv[3], $argv[4], $argv[5]);
?>
