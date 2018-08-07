from __future__ import absolute_import
from __future__ import unicode_literals
import logging
#from tornado.ioloop import IOLoop
from tornado import ioloop
import serial
from tornado import gen
from tornado.iostream import StreamClosedError
from tornado.tcpserver import TCPServer
from tornado.options import options, define
import os
import platform
import socket
import struct

BROADCAST_IP = '192.168.30.255'
DEFAULT_PORT = 9


define("port", default=9888, help="TCP port to listen on")
logger = logging.getLogger(__name__)


#打开串口
baudRate=9600       #波特率
print("os=%s"%(platform.system()))
sysstr = platform.system()
if(sysstr =="Windows"):
    ser1=serial.Serial("COM1",baudRate,timeout=0.5)
    ser2=serial.Serial("COM2",baudRate,timeout=0.5)
    ser3=serial.Serial("COM3",baudRate,timeout=0.5)
    ser4=serial.Serial("COM4",baudRate,timeout=0.5)
elif(sysstr == "Linux"):
    ser1=serial.Serial("/dev/ttyUSB0",baudRate,timeout=0.5)
    ser2=serial.Serial("/dev/ttyUSB1",baudRate,timeout=0.5)
    ser3=serial.Serial("/dev/ttyUSB2",baudRate,timeout=0.5)
    ser4=serial.Serial("/dev/ttyUSB3",baudRate,timeout=0.5)


print("参数设置 ，波特率=%d"%(baudRate))


def create_magic_packet(macaddress):
    """
    Create a magic packet which can be used for wake on lan using the
    mac address given as a parameter.

    Keyword arguments:
    :arg macaddress: the mac address that should be parsed into a magic
                     packet.

    """
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 17:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format')

    # Pad the synchronization stream
    data = b'FFFFFFFFFFFF' + (macaddress * 20).encode()
    send_data = b''

    # Split up the hex values in pack
    for i in range(0, len(data), 2):
        send_data += struct.pack(b'B', int(data[i: i + 2], 16))
    return send_data


def send_magic_packet(*macs, **kwargs):
    """
    Wakes the computer with the given mac address if wake on lan is
    enabled on that host.

    Keyword arguments:
    :arguments macs: One or more macaddresses of machines to wake.
    :key ip_address: the ip address of the host to send the magic packet
                     to (default "255.255.255.255")
    :key port: the port of the host to send the magic packet to
               (default 9)

    """
    packets = []
    ip = kwargs.pop('ip_address', BROADCAST_IP)
    port = kwargs.pop('port', DEFAULT_PORT)
    for k in kwargs:
        raise TypeError('send_magic_packet() got an unexpected keyword '
                        'argument {!r}'.format(k))

    for mac in macs:
        packet = create_magic_packet(mac)
        packets.append(packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((ip, port))
    for packet in packets:
        sock.send(packet)
    sock.close()


class EchoServer(TCPServer):
    clients=set()
    @gen.coroutine
    def handle_stream(self, stream, address):
        self.clients.add(stream)
        print("connection num is:", len(self.clients))
        #Connection(stream, address)
        while True:
            try:
                data = yield stream.read_until(b"\n")
                logger.info("Received bytes: %s", data)
                temp = str(data, encoding="utf-8").strip()
                #print(temp)
                if temp is '1':
                    print("on")
                    send_magic_packet('ff.ff.ff.ff.ff.ff', '08-60-6E-75-98-2D', 'F8-B1-56-B5-06-D5',
                                      '10-7B-44-92-F1-B9', 'FFFFFFFFFFFF')
                    ser1.write("1".encode())
                    ser2.write("2".encode())
                    ser3.write("3".encode())
                else:
                    print("off")
                if not data.endswith(b"\n"):
                    data = data + b"\n"
                yield stream.write(data)
            except StreamClosedError:
                logger.warning("Lost client at host %s", address[0])
                self.clients.remove(stream)
                print("connection num is:", len(self.clients))
                break
            except Exception as e:
                #print(e)
                pass

    def ack(self):
        print('ack')
        #len1  = ser1.write("6456456464".encode())
        #len2  = ser2.write("6456456464".encode())
        #len3  = ser3.write("6456456464".encode())
        #print(len1)  # 可以接收中文
        status = os.system("ping 192.168.5.22299")
        #print('-----:'+status)

        for c in self.clients:
            c.write(b'11');


if __name__ == "__main__":
    options.parse_command_line()
    server = EchoServer()
    server.listen(options.port)
    ioloop.PeriodicCallback(server.ack, 3000).start()  # 这里的时间是毫秒
    logger.info("Listening on TCP port %d", options.port)
    ioloop.IOLoop.instance().start()