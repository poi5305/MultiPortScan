<?php
require_once('MultiPortScan.php');
class MultiPortScanTest extends PHPUnit_Framework_TestCase
{
    // ...
    private $multi_port_scan;
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
    public function protocolProvider()
    {
        return [
            ['icmp',true],
            ['tcp',true],
            ['udp',false]
        ];
    }
    /**
     * @dataProvider reflashProvider
     */
    public function testReflash($proto,$expected)
    {
        $this->assertEquals($expected,$this->multi_port_scan->reflash($proto));
    }
    public function reflashProvider()
    {
        return [
            ['icmp',true],
            ['tcp',true],
            ['udp',-1]
        ];
    }

}
