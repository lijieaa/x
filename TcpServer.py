#!/usr/bin/env python3
from __future__ import absolute_import
from __future__ import unicode_literals
import logging
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
import operator as op

#配置
on_commad="PWR ON" #开投影机指令
off_commad="PWR OFF" #关投影机指令
#设备信息
pc_device={
    "04":"08-60-6E-75-98-2D@192.168.0.102",
    "05":"14-DD-A9-56-6B-D0@192.168.0.111"
}
#配置








serial_available=True
BROADCAST_IP = '192.168.30.255'
DEFAULT_PORT = 9


define("port", default=9888, help="TCP port to listen on")
logger = logging.getLogger(__name__)


#打开串口
baudRate=9600       #波特率
print("os=%s"%(platform.system()))
sysstr = platform.system()
if(sysstr =="Windows"):
    try:
        ser0=serial.Serial("COM1",baudRate,timeout=0.5)
        ser1=serial.Serial("COM2",baudRate,timeout=0.5)
        ser2=serial.Serial("COM3",baudRate,timeout=0.5)
        ser3=serial.Serial("COM4",baudRate,timeout=0.5)
    except Exception as e:
        serial_available=False
        print("串口不可用！")
elif(sysstr == "Linux"):
    try:
        ser0=serial.Serial("/dev/ttyUSB0",baudRate,timeout=0.5)
        ser1=serial.Serial("/dev/ttyUSB1",baudRate,timeout=0.5)
        ser2=serial.Serial("/dev/ttyUSB2",baudRate,timeout=0.5)
        ser3=serial.Serial("/dev/ttyUSB3",baudRate,timeout=0.5)
    except Exception as e:
        serial_available=False
        print("串口不可用！")


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
        while True:
            try:
                data = yield stream.read_until(b"\n")
                logger.info("Received bytes: %s", data)
                temp = str(data, encoding="utf-8").strip()
                #off@pc1&pc2$pro1&pro2&pro3
                #on@pc1&pc2$pro1&pro2&pro3
                print(temp)
                de_op = temp.split("@") #设备码操作码数组
                print(de_op[0]) #设备码
                print(de_op[1])#操作码
                if(op.eq(de_op[1],"1")):#开
                    if(op.eq("04",de_op[0])):
                        send_magic_packet('ff.ff.ff.ff.ff.ff',pc_device["04"].split("@")[0],'FFFFFFFFFFFF')
                    elif(op.eq("05",de_op[0])):
                        send_magic_packet('ff.ff.ff.ff.ff.ff', pc_device["05"].split("@")[0], 'FFFFFFFFFFFF')
                    elif(op.eq("01",de_op[0])):
                        if (serial_available):
                            ser0.write(on_commad.encode())
                            ser0.flush()
                    elif (op.eq("02",de_op[0])):
                        if (serial_available):
                            ser1.write(on_commad.encode())
                            ser1.flush()
                    elif (op.eq("03",de_op[0])):
                        if (serial_available):
                            ser2.write(on_commad.encode())
                            ser2.flush()
                    elif (op.eq("04",de_op[0])):
                        if (serial_available):
                            ser3.write(on_commad.encode())
                            ser3.flush()
                else:#关
                    if (op.eq("04",de_op[0])):
                        for c in self.clients:
                          c.write(data)
                    elif (op.eq("05",de_op[0])):
                        for c in self.clients:
                          c.write(data)
                    elif (op.eq("01",de_op[0])):
                        if (serial_available):
                            ser0.write(off_commad.encode())
                            ser0.flush()
                    elif (op.eq("02",de_op[0])):
                        if (serial_available):
                            ser1.write(off_commad.encode())
                            ser1.flush()
                    elif (op.eq("03",de_op[0])):
                        if (serial_available):
                            ser2.write(off_commad.encode())
                            ser2.flush()
                    elif (op.eq("04",de_op[0])):
                        if (serial_available):
                            ser3.write(off_commad.encode())
                            ser3.flush()
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
        status04 = os.system("ping "+pc_device["04"].split("@")[1]+" -c 1")
        #print(status04)
        if(status04):
            for c in self.clients:
                c.write(b"04@5")
        else:
            for c in self.clients:
                c.write(b"04@6")
        status05 = os.system("ping "+pc_device["05"].split("@")[1]+" -c 1")
        #print(status05)
        if (status05):
            for c in self.clients:
                c.write(b"05@5")
        else:
            for c in self.clients:
                c.write(b"05@6")


if __name__ == "__main__":
    options.parse_command_line()
    server = EchoServer()
    server.listen(options.port)
    ioloop.PeriodicCallback(server.ack, 10*1000).start()  # 这里的时间是毫秒
    logger.info("Listening on TCP port %d", options.port)
    ioloop.IOLoop.instance().start()
