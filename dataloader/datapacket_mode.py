from enum import Enum


class DatapacketMode(Enum):
    SYSCALL = 1
    NETWORKPACKET = 2
    BOTH = 3
