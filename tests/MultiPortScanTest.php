<?php
require_once('MultiPortScan.php');
class MultiPortScanTest extends PHPUnit_Framework_TestCase
{
    // ...
    private $multi_port_scan;
    public function __construct()
    {
        $this->multi_port_scan = new MultiPortScan;
    }
    /**
     * @dataProvider protocolProvider
     */
    public function testProtocolSupport($proto,$expected)
    {
        $ret = $this->multi_port_scan->proto_is_supported($proto);
        // Assert
        $this->assertEquals($expected, $ret);
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
            ['udp',false]
        ];
    }

}
