import logging
#from tornado.ioloop import IOLoop
from tornado import ioloop
import serial
from tornado import gen
from tornado.iostream import StreamClosedError
from tornado.tcpserver import TCPServer
from tornado.options import options, define
import os

define("port", default=9888, help="TCP port to listen on")
logger = logging.getLogger(__name__)


#打开串口
serialPort="COM1"   #串口
baudRate=9600       #波特率
ser=serial.Serial(serialPort,baudRate,timeout=0.5)
print("参数设置：串口=%s ，波特率=%d"%(serialPort,baudRate))


class EchoServer(TCPServer):
    clients=set()
    @gen.coroutine
    def handle_stream(self, stream, address):
        self.clients.add(stream)
        while True:
            try:
                data = yield stream.read_until(b"\n")
                logger.info("Received bytes: %s", data)
                if not data.endswith(b"\n"):
                    data = data + b"\n"
                yield stream.write(data)
            except StreamClosedError:
                logger.warning("Lost client at host %s", address[0])
                break
            except Exception as e:
                print(e)

    def ack(self):
        print('ack')
        len  = ser.write("6456456464".encode())
        print(len)  # 可以接收中文
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