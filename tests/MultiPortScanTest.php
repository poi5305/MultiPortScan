<?php
require_once('../MultiPortScan.php');
class MultiPortScanTest extends PHPUnit_Framework_TestCase
{
    // ...
    private $multi_port_scan;
	/**
	 * Initializes private variable for tests
	 */
    public function setUp()
    {
        $this->multi_port_scan = new MultiPortScan;
    }
    /**
     * @dataProvider protocolProvider
     */
    public function testProtocolSupport($proto,$expected)
    {
        $this->assertEquals($expected,$this->multi_port_scan->proto_is_supported($proto));
    }
	/**
	 * Data provider for testProtocolSupport(...)
	 */
    public function protocolProvider()
    {
        return [
            ['icmp',true],
            ['tcp',true],
            ['udp',true],
			['dns',false]
        ];
    }
    /**
     * @dataProvider reflashProvider
     */
    public function testReflash($proto,$expected)
    {
		$ret = $this->multi_port_scan->reflash($proto);
		echo "TestReflash .. reflash returns: " . var_export($ret,1) . " for protocol: $proto\n";
        $this->assertEquals($expected,$ret);
    }
	/**
	 * Data provider for testReflash(...)
	 */
    public function reflashProvider()
    {
        return [
            ['icmp',0],
            ['tcp',0],
            ['udp',0],
			['dns',-1]
        ];
    }
	/**
	 * @dataProvider UDPPortRangeProvider
	 */
	public function testScanUDPPortRange($start,$end,$timeout,$expected)
	{
		$testIP = '127.0.0.1';
		$this->multi_port_scan->set_verbose(true);
		$this->assertEquals($expected,$this->multi_port_scan->scan_udp($testIP,$start,$end,$timeout));
	}
	/**
	 * Data provider for UDPPortRangeProvider
	 */
	public function UDPPortRangeProvider()
	{
		return [
			[100,1,1,-1],
			[1,5,2,0]
		];
	}

}
