import socket

from keyring.backends import null
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def handshake(sock):
    # SYN message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')

    # Send a response SYN to the client
    response = "(SYN) Request from server"
    sock.sendto(response.encode(), address)
    print(f'message server:  {response}')

    # get AKE message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')

    return address


def SendSizeFile(sock, file_size):
    # Message for get size of the file from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data} ')

    # data=file_size.to_bytes(2, 'little', signed=False)
    print(file_size)

    # Send a response SYN to the client
    sock.sendto(file_size, address)
    print(f'message server:  (PSH) Request size file:{file_size}')

    # get AKE message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')


def make_dictionary_from_file(file_data, packet_size):
    num_packets_to_send = []
    dictionary_packets_to_send = {}
    packets_to_send = [num_packets_to_send, dictionary_packets_to_send]
    start = 0
    i = 0
    while start < len(file_data):
        str_i = str(i)
        packet_num = '/' + str_i
        end = min(start + (packet_size - len(packet_num)), len(file_data))
        packets_to_send[1][str(i)] = file_data[start:end] + packet_num.encode()
        packets_to_send[0].append(i)
        start = end
        i += 1

    return packets_to_send


def send_all_packet(packets_in_window, packets_to_send, sock, address):
    for packet_num in packets_in_window[1].keys():
        send_packet(packets_in_window, packets_to_send, packet_num, sock, address)


def send_packet(packets_in_window, packets_to_send, packet_num, sock, address):
    packets_in_window[1].get(packet_num)[0] = time.time()
    sock.sendto(packets_to_send[1][packet_num], address)


def receive_packet(sock):
    try:
        data, address = sock.recvfrom(1024)
    except socket.error:
        return null
    else:
        return data


def extract_number_packet(recv_pkt):
    packet_num = recv_pkt.split(b'/')[-1].decode()
    return packet_num


def make_window(window, packets_to_send):
    num_packets_in_window = []
    dictionary_packets_in_window = {}
    packets_in_window = [num_packets_in_window, dictionary_packets_in_window]
    for num_packet in range(0, window):
        packets_in_window[1][str(num_packet)] = [0, 0]
        num_packets_in_window.append(num_packet)
        packets_to_send[0].remove(num_packet)

    return packets_in_window


def check_time_out(packets_in_window):
    timeout = 0.5
    for pkt in packets_in_window[1].keys():
        current_time = time.time()
        if current_time - packets_in_window[1].get(pkt)[0] > timeout:
            return True
    return False


def check_fast_recovery(packets_in_window, packets_to_send, recv_packet, sock, address):
    str_packet_num_recv = extract_number_packet(recv_packet)
    int_packet_num_recv = int(str_packet_num_recv)

    '''
    Checking if the ACK we received on the package is present in the window,
    Because it could be that before we received this ACK the size of the window changed
    and some of the packages that were in the window are no longer there.
    But we will still delete the package from the packages that need to be sent in the future
    '''
    if int_packet_num_recv in packets_in_window[0]:

        packets_in_window[0].remove(int_packet_num_recv)  # remove packet number from the list
        packets_in_window[1].pop(str_packet_num_recv)  # remove packet number from the dict
        packets_in_window[0].sort()

        '''
        This loop takes care of the phase before fast recovery,
        and checks if we have reached the stage of fast recovery 
        '''
        for packet_num in packets_in_window[0]:
            if packet_num > int_packet_num_recv:
                break
            packets_in_window[1][packet_num][1] += 1
            if packets_in_window[1][packet_num][1] == 3:
                return True  # we have reached the stage of fast recovery
            send_packet(packets_in_window, packets_to_send, packet_num, sock, address)

        '''
        Checking if there are packets left to send, which are not in the window,
        and if yes, put them in the window and send them
        '''
        if len(packets_to_send[0]) > len(packets_in_window[0]):
            packets_in_window[0].append(packets_to_send[0][0])
            packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]
            packets_to_send[0].remove(packets_to_send[0][0])

            send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)

        return False  # we have not reached the stage of fast recovery

    else:
        packets_to_send[0].remove(int(str_packet_num_recv))


def window_slow_start(packets_in_window, packets_to_send):
    ssthreshold = len(packets_in_window[0]) // 2
    packets_in_window[0].sort()
    for pkt in packets_in_window[0][4:]:
        packets_to_send[0].append(pkt)
        packets_in_window[1].pop(str(pkt))

    packets_to_send[0].sort()
    packets_in_window[0] = packets_in_window[0][:4]

    return ssthreshold


def window_fast_recovery(packets_in_window, packets_in_send):
    ssthreshold = len(packets_in_window[0])
    new_window_size = ssthreshold // 2
    packets_in_window[0].sort()
    for pkt in packets_in_window[0][new_window_size:]:
        packets_in_send[0].append(pkt)
        packets_in_window[1].pop(pkt)

    packets_in_send[0].sort()
    packets_in_window[0] = packets_in_window[0][:new_window_size]

    return ssthreshold


def increase_window(packets_in_window, packets_to_send, sock, address, status, ssthreshold):

    if status == 0 and len(packets_in_window[0]) < ssthreshold:  # 0 = slow start

        for i in range(min(len(packets_in_window[0]), len(packets_to_send[0]))):
            packets_in_window[0].append(packets_to_send[0][0])
            packets_to_send[0].remove(packets_in_window[0][-1])
            packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]

            send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)

    else:  # 0 = AIMD
        packets_in_window[0].append(packets_to_send[0][0])
        packets_to_send[0].remove(packets_in_window[0][-1])
        packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]

        send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)


def main():
    while True:
        app_server_address = 'localhost'
        app_server_port = 5000
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((app_server_address, app_server_port))
        sock.setblocking(True)

        with open('example.txt', 'rb') as f:
            file_data = f.read()

        address = handshake(sock)

        SendSizeFile(sock, str(os.path.getsize('example.txt')).encode())

        packet_size = 1024
        window_size = 4
        ssthreshold = 30
        ack_count = 0
        status = 0  # 0 = Slow_Start / 1 = AIMD

        packets_to_send = make_dictionary_from_file(file_data, packet_size)

        packets_in_window = make_window(min(window_size, len(packets_to_send[1])), packets_to_send)

        send_all_packet(packets_in_window, packets_to_send, sock, address)

        sock.setblocking(False)

        while len(packets_in_window[1]) != 0:
            recv_packet = receive_packet(sock)

            if check_time_out(packets_in_window):
                print("check_time_out" + str(len(packets_in_window[0])))
                ssthreshold = window_slow_start(packets_in_window, packets_to_send)
                send_all_packet(packets_in_window, packets_to_send, sock, address)
                status = 0

            if recv_packet != null:
                ack_count += 1
                need_fast_recovery = check_fast_recovery(packets_in_window, packets_to_send, recv_packet, sock, address)
                if need_fast_recovery:
                    ssthreshold = window_fast_recovery(packets_in_window, packets_to_send)
                    send_all_packet(packets_in_window, packets_to_send, sock, address)
                    print(len(packets_in_window[0]))
                    status = 1
                    ack_count = 0
                elif ack_count == len(packets_in_window[0]):
                    print(len(packets_in_window[0]))
                    increase_window(packets_in_window, packets_to_send, sock, address, status, ssthreshold)
                    ack_count = 0
                recv_packet = null

        else:
            print("finish to send")
            print("len(packets_in_window):")
            print(len(packets_in_window[1]))
            print("len(packets_to_send):")
            print(len(packets_to_send[0]))


if __name__ == "__main__":
    main()
