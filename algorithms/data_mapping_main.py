from collections import deque
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
import re

def main():
    REGEX_NETWORKTRAFFIC = r'.*<..>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}->\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}\).*'
    REGEX_SOURCE_IP_START = '.*<..>'
    REGEX_SOURCE_IP_END = ':\d{1,9}->\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}\).*'
    REGEX_SOURCE_Port_START = '.*<..>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:'
    REGEX_SOURCE_Port_END = '->\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}\).*'
    REGEX_DESTINATION_IP_START = '.*<..>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}->'
    REGEX_DESTINATION_IP_END = ':\d{1,9}\).*'
    REGEX_DESTINATION_Port_START = '.*<..>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,9}->\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:'
    REGEX_DESTINATION_Port_END = '\).*'

    # scenario_path = "/media/sf_VM_ubuntu-20-04-3-LTS/LID-DS-2021_Datensatz/CVE-2017-7529/"
    scenario_path = "/media/sf_VM_ubuntu-20-04-3-LTS/LID-DS-2021_Datensatz_reduziert/CVE-2017-7529/"
    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)
    syscallBuffer = {}
    networkpacketBuffer = {}

    for recording in dataloader.training_data():
        for syscall in recording.syscalls():
            syscallParam = ""
            if 'fd' in syscall.params():
                syscallParam = syscall.params()['fd']
            if 'out_fd' in syscall.params():
                syscallParam = syscall.params()['out_fd']

            regexp = re.compile(REGEX_NETWORKTRAFFIC)
            if regexp.search(syscallParam):
                try:
                    sourceIp = re.search(REGEX_SOURCE_IP_START + '(.+?)' + REGEX_SOURCE_IP_END, syscallParam).group(1)
                    sourcePort = re.search(REGEX_SOURCE_Port_START + '(.+?)' + REGEX_SOURCE_Port_END, syscallParam).group(1)
                    destinationIP = re.search(REGEX_DESTINATION_IP_START + '(.+?)' + REGEX_DESTINATION_IP_END, syscallParam).group(1)
                    destinationPort = re.search(REGEX_DESTINATION_Port_START + '(.+?)' + REGEX_DESTINATION_Port_END, syscallParam).group(1)
                    syscallObj = syscallObject(syscall, sourceIp, sourcePort, destinationIP, destinationPort)

                    if syscall.thread_id() not in syscallBuffer:
                        syscallBuffer[syscall.thread_id()] = deque()
                    syscallBuffer[syscall.thread_id()].append(syscallObj)
                    # printSyscall(syscallObj)
                except:
                    print("Something went wrong")
        print("systemcalls done")

        for packet in recording.packets():
            #networkpacketPartOld()
            key = packet.source_ip_address() + "->" + packet.destination_ip_address()
            if key not in networkpacketBuffer:
                networkpacketBuffer[key] = deque()
            networkpacketBuffer[key].append(packet)

        print("networkpackets done")
        # matchSystemcalls(syscallBuffer, networkpacketBuffer)
        print("DONE")


def networkpacketPartOld(recording, networkpacketBuffer):
    for frame in recording.packets().frame:
        sourceIp = ""
        sourcePort = ""
        destinationIP = ""
        destinationPort = ""

        if hasattr(frame, 'ipv6'):
            sourceIp = frame.ipv6.host
            destinationIP = frame.ipv6.dst
        elif hasattr(frame, 'ip'):
            sourceIp = frame.ip.host
            destinationIP = frame.ip.dst
        elif hasattr(frame, 'arp'):
            sourceIp = frame.arp.src_proto_ipv4
            destinationIP = frame.arp.dst_proto_ipv4
        else:
            print("NO IP")

        if hasattr(frame, 'tcp'):
            sourcePort = frame.tcp.port
            destinationPort = frame.tcp.dstport
        elif hasattr(frame, 'udp'):
            sourcePort = frame.udp.port
            destinationPort = frame.udp.dstport
        elif hasattr(frame, 'sll'):
            print("sll")
        else:
            print("NO PORT")

        timestamp_datetime = frame.sniff_time
        timestamp_unix_in_ns = re.sub('\.', '', frame.sniff_timestamp)
        time = frame.frame_info.time

        networkpacketObj = networkpacketObject(sourceIp, sourcePort, destinationIP, destinationPort, timestamp_datetime,
                                               timestamp_unix_in_ns, time)
        key = sourceIp + "->" + destinationIP
        if key not in networkpacketBuffer:
            networkpacketBuffer[key] = deque()
        networkpacketBuffer[key].append(networkpacketObj)
        # printNetworkpacketOld(networkpacketObj)

def printNetworkpacket(packet):
    print(f"sourceIp: {packet.source_ip_address()}")
    print(f"sourcePort: {packet.source_port()}")
    print(f"destIP: {packet.destination_ip_address()}")
    print(f"destPort: {packet.destination_port()}")
    print(f"timestamp_datetime: {packet.timestamp_datetime()}")
    print(f"timestamp_unix_in_ns: {packet.timestamp_unix_in_ns()}")

def printSyscall(syscallObject):
    print(f"sourceIp: {syscallObject.sourceIp}")
    print(f"sourcePort: {syscallObject.sourcePort}")
    print(f"destIP: {syscallObject.destinationIP}")
    print(f"destPort: {syscallObject.destinationPort}")
    print(f"timestamp_datetime: {syscallObject.timestamp_datetime}")
    print(f"timestamp_unix_in_ns: {syscallObject.timestamp_unix_in_ns}")
    print(f"thread_id: {syscallObject.thread_id}")
    print(f"process_name: {syscallObject.process_name}")
    print(f"process_id: {syscallObject.process_id}")

class syscallObject:
  def __init__(self, syscall, sourceIp, sourcePort, destinationIP, destinationPort):
      self.sourceIp = sourceIp
      self.sourcePort = sourcePort
      self.destinationIP = destinationIP
      self.destinationPort = destinationPort
      self.timestamp_datetime = syscall.timestamp_datetime()
      self.timestamp_unix_in_ns = syscall.timestamp_unix_in_ns()
      self.thread_id = syscall.thread_id()
      self.process_name = syscall.process_name()
      self.process_id = syscall.process_id()

def printNetworkpacketOld(networkpacketObject):
    print(f"sourceIp: {networkpacketObject.sourceIp}")
    print(f"sourcePort: {networkpacketObject.sourcePort}")
    print(f"destIP: {networkpacketObject.destinationIP}")
    print(f"destPort: {networkpacketObject.destinationPort}")
    print(f"timestamp_datetime: {networkpacketObject.timestamp_datetime}")
    print(f"timestamp_unix_in_ns: {networkpacketObject.timestamp_unix_in_ns}")
    print(f"time: {networkpacketObject.time}")

class networkpacketObject:
  def __init__(self, sourceIp, sourcePort, destinationIP, destinationPort, timestamp_datetime, timestamp_unix_in_ns, time):
      self.sourceIp = sourceIp
      self.sourcePort = sourcePort
      self.destinationIP = destinationIP
      self.destinationPort = destinationPort
      self.timestamp_datetime = timestamp_datetime
      self.timestamp_unix_in_ns = timestamp_unix_in_ns
      self.time = time

def matchNetworkpackets(syscallBuffer, networkpacketBuffer):
    matchCounter = 0
    for networkConnection in networkpacketBuffer:
        for networkpacket in networkpacketBuffer[networkConnection]:
            matchCounterNetworkpacket = 0
            for thread in syscallBuffer:
                for syscall in syscallBuffer[thread]:
                    checkSourceIp = syscall.sourceIp == networkpacket.sourceIp
                    checkSourcePort = syscall.sourcePort == networkpacket.sourcePort
                    checkDestinationIP = syscall.destinationIP == networkpacket.destinationIP
                    checkDestinationPort = syscall.destinationPort == networkpacket.destinationPort
                    checkTime1 = int(syscall.timestamp_unix_in_ns) >= int(networkpacket.timestamp_unix_in_ns)
                    checkTime2 = int(syscall.timestamp_unix_in_ns) <= int(networkpacket.timestamp_unix_in_ns) + 1000000000
                    checkList = [checkSourceIp, checkSourcePort, checkDestinationIP, checkDestinationPort, checkTime1, checkTime2]
                    if all(checkList):
                        matchCounter = matchCounter + 1
                        matchCounterNetworkpacket = matchCounterNetworkpacket + 1
                        # print('--- MATCH ---')
                        # print(f"timestamp_datetime:     networkpacket: {networkpacket.timestamp_datetime}   syscall: {syscall.timestamp_datetime}")
                        # print(f"timestamp_unix_in_ns:   networkpacket: {networkpacket.timestamp_unix_in_ns}   syscall: {syscall.timestamp_unix_in_ns}")
                        # print(' ')
            print(f"Auf ein Netzwerkpaket: {matchCounterNetworkpacket} Systemcalls")
    print(f"Match counter: {matchCounter}")

def matchSystemcalls(syscallBuffer, networkpacketBuffer):
    matchCounter = 0
    for thread in syscallBuffer:
        for syscall in syscallBuffer[thread]:
            matchCounterSyscall = 0
            for networkConnection in networkpacketBuffer:
                for networkpacket in networkpacketBuffer[networkConnection]:
                    checkSourceIp = syscall.sourceIp == networkpacket.sourceIp
                    checkSourcePort = syscall.sourcePort == networkpacket.sourcePort
                    checkDestinationIP = syscall.destinationIP == networkpacket.destinationIP
                    checkDestinationPort = syscall.destinationPort == networkpacket.destinationPort
                    checkTime1 = int(syscall.timestamp_unix_in_ns) >= int(networkpacket.timestamp_unix_in_ns)
                    checkTime2 = int(syscall.timestamp_unix_in_ns) <= int(networkpacket.timestamp_unix_in_ns) + 1000000000
                    checkList = [checkSourceIp, checkSourcePort, checkDestinationIP, checkDestinationPort, checkTime1, checkTime2]
                    if all(checkList):
                        matchCounter = matchCounter + 1
                        matchCounterSyscall = matchCounterSyscall + 1
            print(f"Auf einen Systemcall: {matchCounterSyscall} Netzwerkpatete")
    print(f"Match counter: {matchCounter}")


if __name__ == '__main__':
    main()
