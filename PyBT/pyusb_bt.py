import binascii
import logging

import sys

import usb.core
import usb.util

from scapy.layers.bluetooth import *
from scapy.supersocket import SuperSocket

USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xE0
USB_DEVICE_SUB_CLASS_RF_CONTROLLER = 0x01
USB_DEVICE_PROTOCOL_BLUETOOTH = 0x01

USB_ENDPOINT_HCI_CMD = 0x00


log = logging.getLogger("PyBT.stack")


class PyUSBBluetoothUserSocketException(Exception):
    pass


class PyUSBBluetoothUserSocket(SuperSocket):
    desc = "read/write Bluetooth HCI with pyUSB"

    def __init__(self, pyusb_dev):
        self.pyusb_dev = pyusb_dev

    def send_command(self, cmd):
        opcode = cmd.opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.code == 0xe and r.opcode == opcode:
                if r.status != 0:
                    raise BluetoothCommandError(
                        "Command %x failed with %x" % (opcode, r.status))
                return r

    def recv(self, x=512):
        # FIXME: Don't know how many bytes to expect here,
        # using 512 bytes -- probably won't fly if there's another event right
        # after it?
        data_array = self.pyusb_dev.read(0x81, 512, 1000)
        data = ''.join([chr(c) for c in data_array])  # Ugh.. array return val
        data = "\4" + data  # Prepend H4 'Event' packet indicator
        print "recv: " + binascii.hexlify(data)
        scapy_packet = HCI_Hdr(data)
        return scapy_packet

    def readable(self, timeout=0):
        (ins, outs, foo) = select([self.ins], [], [], timeout)
        return len(ins) > 0

    def send(self, scapy_packet):
        data = str(scapy_packet)
        print "send: " + binascii.hexlify(data)
        data = data[1:]  # Cut off the H4 'Command' packet indicator (0x02)
        sent_len =  self.pyusb_dev.ctrl_transfer(
            bmRequestType=0x20,
            bRequest=0x00,
            wValue=0x00,
            wIndex=0x00,
            data_or_wLength=data)
        l = len(data)
        if sent_len != l:
            raise PyUSBBluetoothUserSocketException(
                "Send failure. Sent %u instead of %u bytes" % (sent_len, l))

    def flush(self):
        while self.readable():
            self.recv()


def find_bt_controllers():
    # TODO: This will only find non-composite Bluetooth controllers.
    devs = usb.core.find(
        bDeviceClass=USB_DEVICE_CLASS_WIRELESS_CONTROLLER,
        bDeviceSubClass=USB_DEVICE_SUB_CLASS_RF_CONTROLLER,
        bDeviceProtocol=USB_DEVICE_PROTOCOL_BLUETOOTH,
        find_all=True)
    return list(devs)


def socket_for_first_adapter():
    pyusb_devs = find_bt_controllers()
    if len(pyusb_devs) == 0:
        raise Exception("No Bluetooth controllers found!")
        sys.exit(-1)
    elif len(pyusb_devs) > 1:
        log.warn("More than 1 Bluetooth controller found, "
                 "using the first one...")
    pyusb_dev = pyusb_devs[0]
    pyusb_dev.set_configuration()

    return PyUSBBluetoothUserSocket(pyusb_dev)
