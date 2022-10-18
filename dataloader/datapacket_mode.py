from enum import Enum


class DatapacketMode(Enum):
    SYSCALL = "systemcall"
    NETWORKPACKET = "networkpacket"
    BOTH = "both"
