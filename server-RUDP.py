import socket
from scapy.all import *
from time import sleep

IP_ADDRESS='localhost'
PORT=31314

class RUDPServer:
    def __init__(self):
        self.IP_ADDRESS = 'localhost'
        self.PORT = 5000

    def createAndSendPackage(self,sock,packet_num,msg,address):
        packet_num=packet_num.to_bytes(1, 'little', signed=False)
        address_server = (address[0],address[1])
        sock.sendto(msg+packet_num,address_server)


    def getMsgAndPM(self,data):
        packet_num = data[-1]
        msg = data[:-1]
        
        return packet_num,msg


    def receiveData(self,sock, packet_num):
        sock.settimeout(2)
        counter = 0
        
        while True:
            try:
                received_data = sock.recvfrom(2048)
                packet_num_recieved,data= self.getMsgAndPM(received_data[0])
                
                if packet_num_recieved < packet_num:
                    continue
                
                if packet_num != packet_num_recieved:
                    return None, None
                
            except socket.timeout as e:
                err = e.args[0]
                # this next if/else is a bit redundant, but illustrates how the
                # timeout exception is setup
                if err == 'timed out':
                    sleep(1)
                    counter += 1
                    
                    if counter == 2:
                        print("Didn't receive ACK - resend")
                        return None, None
                    continue
                else:
                    print(e)
                    sys.exit(1)
            except socket.error as e:
                # Something else happened, handle error, exit, etc.
                print(e)
                sys.exit(1)       
            return received_data  


    def checkConnection(self,data, sock, packet_num, msg, address, last_ack):
        
        # Send last ACK
        self.createAndSendPackage(sock,last_ack[0],last_ack[1],address)
        sleep(0.5)
        
        for c in range(0,2):
                
            if not data:
                self.createAndSendPackage(sock,packet_num+1,msg,address)
                data, address_unchecked = self.receiveData(sock, packet_num+2)
            else:
                return data, address_unchecked 
        if data:
            return data, address_unchecked         
        print('Client left the conversation closing the connection')
        sock.close()
        exit()
        
        
    def handshake(self,sock):
        # SYN message from client //1
        data, address = sock.recvfrom(1024)
        packet_num,data= self.getMsgAndPM(data)
        print(f'message client:{data.decode()}, package number: {packet_num}')

        # Send a response SYN to the client //2
        message = b"(SYN,ACK) Request from server"
        last_ack = (packet_num+1,message)
        self.createAndSendPackage(sock,packet_num+1,message,address)
        print(f'message server:{message.decode()}, package number: {packet_num+1}')

        # get ACK message from client
        data_unchecked, address_unchecked = self.receiveData(sock,packet_num+2)

        if not data_unchecked:
            data_unchecked, address_unchecked = self.checkConnection(data_unchecked, sock, packet_num, message, address, last_ack)
        data = data_unchecked
        address = address_unchecked
        sock.settimeout(None)
        
        packet_num,data= self.getMsgAndPM(data)
        print(f'message client:{data.decode()}, package number: {packet_num}')
        
        return address


    def SendSizeFile(self,sock,file_size): 
        # Message for get size of the file from client
        data, address = sock.recvfrom(1024)
        packet_num,data= self.getMsgAndPM(data)
        print(f'message client:{data.decode()}, package number: {packet_num}')
        
        message = file_size
        self.createAndSendPackage(sock,packet_num+1,message, address)
        last_ack = (packet_num+1,message)
        
        # Send a response SYN to the client
        print(f'message server:(DATA,ACK) Request size file: {file_size}, package number: {packet_num+1}')
        
        # get ACK message from client
        data_unchecked, address_unchecked = self.receiveData(sock, packet_num+2)

        if not data_unchecked:
            data_unchecked, address_unchecked = self.checkConnection(data_unchecked, sock, packet_num, message, address,last_ack)
        data = data_unchecked
        address = address_unchecked
        sock.settimeout(None)
        
        packet_num,data= self.getMsgAndPM(data)
        print(f'message client:{data.decode()}, package number: {packet_num}')


    def make_dictionary_from_file(self,file_data, packet_size):
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


    def send_all_packet(self,packets_in_window, packets_to_send, sock, address):
        for packet_num in packets_in_window[1].keys():
            self.send_packet(packets_in_window, packets_to_send, packet_num, sock, address)


    def send_packet(self,packets_in_window, packets_to_send, packet_num, sock, address):
        packets_in_window[1].get(str(packet_num))[0] = time.time()
        sock.sendto(packets_to_send[1][str(packet_num)], address)
        if packet_num==0:
            print(f"message server:(DATA) A package was sent from the HTML file , package number: {int(packet_num)+7}")
            print(f"message client:(ACK) Request from client , package number: {int(packet_num)+8}")
        


    def receive_packet(self,sock):
        try:
            data, address = sock.recvfrom(1024)
        except socket.error:
            return None
        else:
            return data


    def extract_number_packet(self,recv_pkt):
        packet_num = recv_pkt.split(b'/')[-1].decode()
        return packet_num


    def make_window(self,window, packets_to_send):
        num_packets_in_window = []
        dictionary_packets_in_window = {}
        packets_in_window = [num_packets_in_window, dictionary_packets_in_window]
        for num_packet in range(0, window):
            packets_in_window[1][str(num_packet)] = [0, 0]
            num_packets_in_window.append(num_packet)
            packets_to_send[0].remove(num_packet)

        return packets_in_window


    def check_time_out(self,packets_in_window):
        timeout = 0.5
        for pkt in packets_in_window[1].keys():
            current_time = time.time()
            if current_time - packets_in_window[1].get(pkt)[0] > timeout:
                return True
        return False


    def check_fast_recovery(self,packets_in_window, packets_to_send, recv_packet, sock, address):
        str_packet_num_recv = self.extract_number_packet(recv_packet)
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
                packets_in_window[1][str(packet_num)][1] += 1
                if packets_in_window[1][str(packet_num)][1] == 3:
                    return True  # we have reached the stage of fast recovery
                self.send_packet(packets_in_window, packets_to_send, packet_num, sock, address)

            '''
            Checking if there are packets left to send, which are not in the window,
            and if yes, put them in the window and send them
            '''
            if len(packets_to_send[0]) > len(packets_in_window[0]):
                packets_in_window[0].append(packets_to_send[0][0])
                packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]
                packets_to_send[0].remove(packets_to_send[0][0])

                self.send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)

            return False  # we have not reached the stage of fast recovery

        else:
            if int_packet_num_recv in packets_to_send[0]:
                packets_to_send[0].remove(int_packet_num_recv)


    def window_slow_start(self,packets_in_window, packets_to_send):
        ssthreshold = len(packets_in_window[0]) // 2
        packets_in_window[0].sort()
        for pkt in packets_in_window[0][4:]:
            packets_to_send[0].append(pkt)
            packets_in_window[1].pop(str(pkt))

        packets_to_send[0].sort()
        packets_in_window[0] = packets_in_window[0][:4]
        for num in packets_in_window[0]:
            packets_in_window[1][str(num)] = [0, 0]

        return ssthreshold


    def window_fast_recovery(self,packets_in_window, packets_in_send):
        ssthreshold = len(packets_in_window[0])
        new_window_size = max(4, ssthreshold // 2)
        packets_in_window[0].sort()
        for pkt in packets_in_window[0][new_window_size:]:
            packets_in_send[0].append(pkt)
            packets_in_window[1].pop(str(pkt))

        packets_in_send[0].sort()
        packets_in_window[0] = packets_in_window[0][:new_window_size]
        for num in packets_in_window[0]:
            packets_in_window[1][str(num)] = [0, 0]

        return ssthreshold


    def increase_window(self,packets_in_window, packets_to_send, sock, address, status, ssthreshold):

        if status == 0 and len(packets_in_window[0]) < ssthreshold:  # 0 = slow start

            for i in range(min(len(packets_in_window[0]), len(packets_to_send[0]))):
                packets_in_window[0].append(packets_to_send[0][0])
                packets_to_send[0].remove(packets_in_window[0][-1])
                packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]

                self.send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)

        else:  # 0 = AIMD
            if len(packets_to_send[0]) > 0:
                packets_in_window[0].append(packets_to_send[0][0])
                packets_to_send[0].remove(packets_in_window[0][-1])
                packets_in_window[1][str(packets_in_window[0][-1])] = [0, 0]

                self.send_packet(packets_in_window, packets_to_send, str(packets_in_window[0][-1]), sock, address)

        
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((IP_ADDRESS, PORT))
        sock.setblocking(True)
        print("'localhost', 30314")

        address=self.handshake(sock)
        
        with open('example.txt', 'rb') as f:
            file_data = f.read()

        self.SendSizeFile(sock,str(os.path.getsize('example.txt')).encode())

        packet_size = 1024
        window_size = 4
        ssthreshold = 30
        ack_count = 0
        timeout_shut_down = 0
        status = 0  # 0 = Slow_Start / 1 = AIMD

        packets_to_send = self.make_dictionary_from_file(file_data, packet_size)

        packets_in_window = self.make_window(min(window_size, len(packets_to_send[1])), packets_to_send)

        self.send_all_packet(packets_in_window, packets_to_send, sock, address)

        sock.setblocking(False)

        while len(packets_in_window[1]) != 0:
            recv_packet = self.receive_packet(sock)

            if self.check_time_out(packets_in_window):
                timeout_shut_down += 1
                if timeout_shut_down == 3:
                    break
                print("check_time_out" + str(len(packets_in_window[0])))
                ssthreshold = self.window_slow_start(packets_in_window, packets_to_send)
                self.send_all_packet(packets_in_window, packets_to_send, sock, address)
                status = 0

            if recv_packet:
                timeout_shut_down = 0
                ack_count += 1
                need_fast_recovery = self.check_fast_recovery(packets_in_window, packets_to_send, recv_packet, sock, address)
                if need_fast_recovery:
                    ssthreshold = self.window_fast_recovery(packets_in_window, packets_to_send)
                    self.send_all_packet(packets_in_window, packets_to_send, sock, address)
                    print(len(packets_in_window[0]))
                    status = 1
                    ack_count = 0
                elif ack_count == len(packets_in_window[0]):
                    self.increase_window(packets_in_window, packets_to_send, sock, address, status, ssthreshold)
                    ack_count = 0
                recv_packet = None

        else:
            print("The HTML file has been sent successfully")


def main():
    rudp_server = RUDPServer()
    rudp_server.start()


if __name__ == "__main__":
    main()
