import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket 
import logging
# from ..util import simsocket
import struct
import socket
import util.bt_utils as bt_utils
# from ..util import bt_utils
import hashlib
import argparse
import pickle
import time
import matplotlib.pyplot as plt
"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512*1024
HEADER_LEN = struct.calcsize("HBBHHIIII")
MAX_PAYLOAD=1024
#sending_now is a dict , storing  dict[address(ip,port)]=ex_sending_chunk.As one peer can send multiple chunks to different peers.
sending_now=dict()
#receiving_now is a dict, storing  dict[address(ip,port)]=ex_downloading_chunk.As one peer can receive several chunks from different peers.
receiving_now=dict()
config = None
ex_output_file = None
#dict [chunkname,bytes()]
ex_received_chunk = dict()
ex_downloading_chunkhash = ""
#next_sequence_num is a dict , dict[address(ip,port)]=next_sequence_number
next_sequence_num_dict=dict()
expected_sequence_num_dict=dict()
#cwnd_dict is a dict, dict[address(ip,port)]=cwnd
cwnd_dict=dict()
#ssthresh_dict is a dict, dict[address(ip,port)]=ssthresh
ssthresh_dict=dict()
#time_out_dict is a dict, dict[address(ip,port)]=time_out
time_out_dict=dict()
base_num_dict=dict()
#time_dict is used to store the start time of base packet
time_dict=dict()
#used to decide in slow start state or congestion control state.
state_dict=dict()
#used to store the estimated rtt
estimated_rtt_dict=dict()
#used to store the devrtt
dev_rtt_dict=dict()
send_rev_dict = dict()#key ip address value list (seq(already received))
buffer = dict()
#缓存
alpha=0.125
beta=0.25
#used to record window_size
win_size=[]
#used to record time
time_list=[]
#used to record the crashed peer, so if receiver need to resend whohas,then should avoid them
crashed_peer=[]
#it is used to record last time, the receiver received a packet from one peer
receive_time_dict=dict()
# it is used to record the duplicate count if it is 3 then retransmit
duplicate_count_dict=dict()
# it is used to record the sequence number of duplicate packet
duplicate_seq_num_dict=dict()
#used to store whether fast retransmition or not key:address value:list(contains the already retransmited sequence num)
fast_retran_or_not_dict=dict()
#used to store the farest ack num i have received
farest_ack_num_dict=dict()
#it is used to record the datahash not yet downloaded completely
download_not_finished_list=list()
def process_download(sock,chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash
    ex_output_file = outputfile
    #Step 1: read chunkhash to be downloaded from chunkfile
    with open(chunkfile, 'r') as cf:
        while True:
          line=cf.readline()
          if not line:
            break
          index,datahash_str=line.strip().split(" ")
          ex_received_chunk[datahash_str] = bytes()
          ex_downloading_chunkhash = datahash_str
          download_not_finished_list.append(datahash_str)
          download_hash = bytes()
          # hex_str to bytes
          datahash = bytes.fromhex(datahash_str)
          print(f"datahash: {bytes.hex(datahash)}")
          download_hash = download_hash + datahash
    
          # Step2: make WHOHAS pkt
          # |2byte magic|1byte type |1byte team|
          # |2byte  header len  |2byte pkt len |
          # |      4byte  seq                  |
          # |      4byte  ack                  | 
          whohas_header = struct.pack("!HBBHHIIII", 52305,35, 0, HEADER_LEN, socket.htons(HEADER_LEN+len(download_hash)), socket.htonl(0), socket.htonl(0),socket.htonl(0),0)
          whohas_pkt = whohas_header + download_hash

          # Step3: flooding whohas to all peers in peer list
          peer_list = config.peers
          for p in peer_list:
            if int(p[0]) != config.identity:
              sock.sendto(whohas_pkt, (p[1], int(p[2])))    



def process_inbound_udp(sock):
    # Receive pkt
    global config
    global ex_sending_chunkhash
    global sending_now
    global receiving_now
    global next_sequence_num_dict
    global cwnd_dict
    global ssthresh_dict
    global time_out_dict
    global base_num_dict
    global time_dict
    global state_dict
    global expected_sequence_num_dict
    global alpha
    global beta
    global buffer
    global time_list
    global win_size
    global send_rev_dict
    global receive_time_dict
    global fast_retran_or_not_dict
    global download_not_finished_list
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    #Valid is used to check whether it is a dup sequence，it is only used in ack packet
    Magic, Valid, Type,hlen, plen, Seq, Ack,Dup,Farest= struct.unpack("!HBBHHIIII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        chunkhash_str=bytes.hex(get_chunk_hash)
        #receive the first ihave message from one particular peer
        if chunkhash_str not in receiving_now.values():
            receiving_now[from_addr]=chunkhash_str
            expected_sequence_num_dict[from_addr]=0
            receive_time_dict[from_addr]=time.time()
            buffer[from_addr]=dict()
            # send back GET pkt
            get_header = struct.pack("!HBBHHIIII", 52305, 0, 2 , HEADER_LEN, HEADER_LEN+len(get_chunk_hash), 0, 0,0,0)
            print("Send get message")
            get_pkt = get_header+get_chunk_hash
            sock.sendto(get_pkt, from_addr)

    elif Type == 3:
        # received a DATA pkt
        ex_downloading_chunkhash=receiving_now[from_addr]
        seq_num=Seq
        receive_time_dict[from_addr]=time.time()
        # the seq_num is exactly the receiver wanted.
        print(f"receive sequence_num is {seq_num}, expected_sequence_num is {expected_sequence_num_dict[from_addr]}")

        if seq_num==expected_sequence_num_dict[from_addr]:#exactly equals to the expected_sequence_num_dict
           ex_received_chunk[ex_downloading_chunkhash] += data
           sock.add_log("previous expected")
           sock.add_log(expected_sequence_num_dict[from_addr])
           # send back ACK
           ack_pkt = struct.pack("!HBBHHIIII", 52305,0,  4,HEADER_LEN, HEADER_LEN, 0, Seq,0,0)
           sock.sendto(ack_pkt, from_addr)
           expected_sequence_num_dict[from_addr]=expected_sequence_num_dict[from_addr]+1
           print(expected_sequence_num_dict[from_addr])
           ### while to find the next expected_sequence_num_dict
           while(expected_sequence_num_dict[from_addr] < 512 and (expected_sequence_num_dict[from_addr] in buffer[from_addr].keys())):
                ex_received_chunk[ex_downloading_chunkhash] += buffer[from_addr][expected_sequence_num_dict[from_addr]]
                buffer[from_addr].pop(expected_sequence_num_dict[from_addr])
                expected_sequence_num_dict[from_addr]=expected_sequence_num_dict[from_addr]+1
           sock.add_log("next expected")
           sock.add_log(expected_sequence_num_dict[from_addr])
        else:
           #put it into cache and send back duplicate ack sequence
           buffer[from_addr][seq_num] = data
           temp=expected_sequence_num_dict[from_addr]
           temp+=1
           # calculate the farest i have received
           while(temp<512 and (temp in buffer[from_addr].keys())):
            temp+=1
           ack_pkt = struct.pack("!HBBHHIIII", 52305,1,  4,HEADER_LEN, HEADER_LEN, 0, Seq , expected_sequence_num_dict[from_addr],temp)
           sock.sendto(ack_pkt, from_addr)
        
        print(f"data len: {len(ex_received_chunk[ex_downloading_chunkhash])} , seq: {socket.ntohl(Seq)} ,downloading chunkhas: {ex_downloading_chunkhash}")
        # see if all  finished
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]
            download_not_finished_list.remove(ex_downloading_chunkhash)
        if len(download_not_finished_list)==0:
            sock.add_log("finish all")
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)
            # # add to this peer's haschunk:
            # config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]
            # # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            # print(f"GOT {ex_output_file}")
            # # The following things are just for illustration, you do not need to print out in your design.
            # sha1 = hashlib.sha1()
            # sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            # received_chunkhash_str = sha1.hexdigest()
            # print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            # print(f"Received chunkhash: {received_chunkhash_str}" )
            # success = ex_downloading_chunkhash==received_chunkhash_str
            # print(f"Successful received: {success}")
            # if success:
            #     print("Congrats! You have completed the example!")
            # else:
            #     print("Example fails. Please check the example files carefully.")

    elif Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender want
        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:
            # send back IHAVE pkt
            ex_sending_chunkhash = chunkhash_str
            ihave_header = struct.pack("!HBBHHIIII",52305, 0, 1,HEADER_LEN, HEADER_LEN+len(whohas_chunk_hash), 0, 0,0,0)
            ihave_pkt = ihave_header+whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)


    elif Type == 2:
        # received a GET pkt
        # find get_chunk_hash
        get_chunk_hash=data[:20]
        chunkhash_str=bytes.hex(get_chunk_hash)
        # don't reach max send  and initialize all the variables
        if from_addr not in sending_now.keys() and len(sending_now)<config.max_conn:
            sending_now[from_addr]=chunkhash_str
            cwnd_dict[from_addr]=1
            ssthresh_dict[from_addr]=64
            #if time_out is 0 then use estimated_rtt_dict else  use config.timeout
            time_out_dict[from_addr]=config.timeout
            estimated_rtt_dict[from_addr]=0
            dev_rtt_dict[from_addr]=0
            base_num_dict[from_addr]=0
            next_sequence_num_dict[from_addr]=1
            state_dict[from_addr]=1
            time_dict[from_addr]=dict()
            time_dict[from_addr][0]=time.time()
            send_rev_dict[from_addr]=list()
            duplicate_count_dict[from_addr]=0
            duplicate_seq_num_dict[from_addr]=0
            fast_retran_or_not_dict[from_addr]=list()
            chunk_data = config.haschunks[chunkhash_str][:MAX_PAYLOAD]
            # send back DATA
            data_header = struct.pack("!HBBHHIIII", 52305,0, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), 0, 0,0,0)
            sock.sendto(data_header+chunk_data, from_addr)
            #start to time
        
    elif Type == 4:
            # received an ACK pkt
            ack_num = Ack
            if from_addr in sending_now.keys():
                ex_sending_chunkhash=sending_now[from_addr] 
            #update rtt time ,because config.timeout is zero
            if config.timeout==0:
                estimated_rtt_dict[from_addr]=(1-alpha)*estimated_rtt_dict[from_addr]+alpha*(time.time()-time_dict[from_addr][ack_num])
                dev_rtt_dict[from_addr]=(1-beta)*dev_rtt_dict[from_addr]+beta*abs(time.time()-time_dict[from_addr][ack_num]-estimated_rtt_dict[from_addr])
                time_out_dict[from_addr]=estimated_rtt_dict[from_addr]+4*dev_rtt_dict[from_addr] 
            if state_dict[from_addr]==1:#slow start  
                sock.add_log("slow start")
                if  Valid==0 and ack_num not in send_rev_dict[from_addr]:#new ack
                    duplicate_count_dict[from_addr]=0
                    duplicate_seq_num_dict[from_addr]=ack_num
                    cwnd_dict[from_addr]=cwnd_dict[from_addr]+1
                    send_rev_dict[from_addr].append(ack_num)
                    if len(send_rev_dict[from_addr]) == 512: #sending finished
                        if from_addr in sending_now.keys():
                            sock.add_log("send finished")
                            print(f"finished sending {ex_sending_chunkhash}")
                            plt.title("window size")
                            plt.xlabel("time")
                            plt.ylabel("cwnd size")
                            plt.plot(time_list,win_size)
                            plt.savefig("res.png")
                            sock.add_log("save png")
                            sending_now.pop(from_addr)
                            return
                    #used for ploting
                    win_size.append((int)(cwnd_dict[from_addr]))
                    time_list.append(time.time())
                    if int(cwnd_dict[from_addr])>=ssthresh_dict[from_addr]:
                        state_dict[from_addr]=2
                        sock.add_log("cwnd>=ssthresh into congestion avoidance")
                    sock.add_log("previous base")
                    sock.add_log(base_num_dict[from_addr])
                    if ack_num==base_num_dict[from_addr]: 
                        base_num_dict[from_addr]=ack_num+1
                        while(base_num_dict[from_addr] < 512 and base_num_dict[from_addr] in send_rev_dict[from_addr]):
                            base_num_dict[from_addr] += 1
                        sock.add_log("new base")
                        sock.add_log(base_num_dict[from_addr])
                        #transmit 
                        #transmit package [next_sequence_num_dict[from_addr],base_num_dict[from_addr]+cwnd_dict[from_addr]-1]
                        # print(f"cwnd is {cwnd_dict[from_addr]}, ssthresh is {ssthresh_dict[from_addr]}, next_sequence_num is {next_sequence_num_dict[from_addr]},base_num is {base_num_dict[from_addr]}")
                        if next_sequence_num_dict[from_addr]<=511 and next_sequence_num_dict[from_addr]<=base_num_dict[from_addr]+int(cwnd_dict[from_addr])-1:
                            sock.add_log("window size")
                            sock.add_log(int(cwnd_dict[from_addr]))
                            sock.add_log("previous next seq")
                            sock.add_log(next_sequence_num_dict[from_addr])
                            for i in range(next_sequence_num_dict[from_addr],min(512,base_num_dict[from_addr]+int(cwnd_dict[from_addr]))):
                                if i*MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                    break
                                else:
                                    #set up timer
                                    time_dict[from_addr][i] = time.time()
                                    left = i* MAX_PAYLOAD
                                    right = min((i+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                                    next_data = config.haschunks[ex_sending_chunkhash][left: right]
                                    # send next data
                                    data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), i, 0,0,0)
                                    sock.sendto(data_header+next_data, from_addr)
                            next_sequence_num_dict[from_addr]=base_num_dict[from_addr]+int(cwnd_dict[from_addr])
                            sock.add_log("next seq")
                            sock.add_log(next_sequence_num_dict[from_addr])
                elif Valid!=0 and ack_num not in send_rev_dict[from_addr] :#exists packet loss ,we need duplicate ack
                    send_rev_dict[from_addr].append(ack_num)
                    if len(send_rev_dict[from_addr]) == 512: #sending finished
                        if from_addr in sending_now.keys():
                            sock.add_log("send finished")
                            print(f"finished sending {ex_sending_chunkhash}")
                            plt.title("window size")
                            plt.xlabel("time")
                            plt.ylabel("cwnd size")
                            plt.plot(time_list,win_size)
                            plt.savefig("res.png")
                            sock.add_log("save png")
                            sending_now.pop(from_addr)
                            return
                    sock.add_log("packet loss and duplicate ack")
                    duplicate_seq_num=Dup
                    if duplicate_seq_num !=duplicate_seq_num_dict[from_addr]:#a new duplicate_seq_num
                        duplicate_seq_num_dict[from_addr]=duplicate_seq_num
                        duplicate_count_dict[from_addr]=1
                    else:#the same duplicate_seq_num
                        duplicate_count_dict[from_addr]+=1
                        #retransmit , we can only fast retransmission once for the specific packet
                        if (duplicate_seq_num not in fast_retran_or_not_dict[from_addr]) and duplicate_count_dict[from_addr]==3:
                            # add it to the retransmit list in order to avoid fast retransmit several times
                            fast_retran_or_not_dict[from_addr].append(duplicate_seq_num)
                            sock.add_log("retransmit")
                            sock.add_log(duplicate_seq_num)
                            #retransmit packet lost
                            ssthresh_dict[from_addr]=max(int(cwnd_dict[from_addr]/2),2)
                            cwnd_dict[from_addr]=1
                            #retransmit the duplicate sequence num packet
                            if duplicate_seq_num* MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                pass
                            else:
                                time_dict[from_addr][duplicate_seq_num]=time.time()
                                left=duplicate_seq_num*MAX_PAYLOAD
                                right=min((duplicate_seq_num+1)*MAX_PAYLOAD,CHUNK_DATA_SIZE)
                                next_data=config.haschunks[ex_sending_chunkhash][left:right]
                                # send loss packet data
                                data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), duplicate_seq_num, 0,0,0)
                                sock.sendto(data_header+next_data, from_addr)
                            # retransmit the packet [Farest,next_sequence_num_dict[from_addr]-1] not yet received ack
                            for sequence_num in range(Farest,min(512,next_sequence_num_dict[from_addr])):
                                if sequence_num not in send_rev_dict[from_addr]:
                                    if sequence_num* MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                        break
                                    else:
                                        time_dict[from_addr][sequence_num]=time.time()
                                        left=sequence_num*MAX_PAYLOAD
                                        right = min((sequence_num+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                                        next_data = config.haschunks[ex_sending_chunkhash][left: right]
                                        # send next data
                                        data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), sequence_num, 0,0,0)
                                        sock.sendto(data_header+next_data, from_addr)
                            


            else:#congestion avoidance
                sock.add_log("congestion avoidance")
                if Valid==0 and ack_num not in send_rev_dict[from_addr]:#new ack
                    sock.add_log("new ack")
                    cwnd_dict[from_addr]=cwnd_dict[from_addr]+1.0/cwnd_dict[from_addr]
                    send_rev_dict[from_addr].append(ack_num)
                    if len(send_rev_dict[from_addr]) == 512: #sending finished
                        if from_addr in sending_now.keys():
                            sock.add_log("send finished")
                            print(f"finished sending {ex_sending_chunkhash}")
                            plt.title("window size")
                            plt.xlabel("time")
                            plt.ylabel("cwnd size")
                            plt.plot(time_list,win_size)
                            plt.savefig("res.png")
                            sock.add_log("save png")
                            sending_now.pop(from_addr)
                            return
                    #used for ploting
                    win_size.append(int(cwnd_dict[from_addr]))
                    time_list.append(time.time())
                    if ack_num==base_num_dict[from_addr]:
                        base_num_dict[from_addr]=ack_num+1           
                        #set up timer
                        while(base_num_dict[from_addr] < 512 and base_num_dict[from_addr] in send_rev_dict[from_addr]):
                            base_num_dict[from_addr] += 1
                        #transmit 
                        #transmit package [next_sequence_num_dict[from_addr],base_num_dict[from_addr]+cwnd_dict[from_addr]-1]
                        if  next_sequence_num_dict[from_addr]<=511 and next_sequence_num_dict[from_addr]<=base_num_dict[from_addr]+int(cwnd_dict[from_addr])-1:
                            for i in range(next_sequence_num_dict[from_addr],min(512,base_num_dict[from_addr]+int(cwnd_dict[from_addr]))):
                                if i*MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                    break
                                else:
                                    time_dict[from_addr][i] = time.time()
                                    left = i* MAX_PAYLOAD
                                    right = min((i+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                                    next_data = config.haschunks[ex_sending_chunkhash][left: right]
                                    # send next data
                                    data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), i, 0,0,0)
                                    sock.sendto(data_header+next_data, from_addr)
                            next_sequence_num_dict[from_addr]=base_num_dict[from_addr]+int(cwnd_dict[from_addr])
                elif Valid!=0 and ack_num not in send_rev_dict[from_addr]:#have duplicated ack
                    #add it into received ack
                    send_rev_dict[from_addr].append(ack_num)
                    if len(send_rev_dict[from_addr]) == 512: #sending finished
                        if from_addr in sending_now.keys():
                            sock.add_log("send finished")
                            print(f"finished sending {ex_sending_chunkhash}")
                            plt.title("window size")
                            plt.xlabel("time")
                            plt.ylabel("cwnd size")
                            plt.plot(time_list,win_size)
                            plt.savefig("res.png")
                            sock.add_log("save png")
                            sending_now.pop(from_addr)
                            return
                    sock.add_log("duplicated ack")
                    duplicate_seq_num=Dup
                    if duplicate_seq_num !=duplicate_seq_num_dict[from_addr]:#a new duplicate_seq_num
                        duplicate_seq_num_dict[from_addr]=duplicate_seq_num
                        duplicate_count_dict[from_addr]=1
                    else:#the same duplicate_seq_num
                        duplicate_count_dict[from_addr]+=1
                        #retransmit
                        if (duplicate_seq_num not in fast_retran_or_not_dict[from_addr]) and duplicate_count_dict[from_addr]==3:
                            fast_retran_or_not_dict[from_addr].append(duplicate_seq_num)
                            sock.add_log("retransmit")
                            sock.add_log(duplicate_seq_num)
                            ssthresh_dict[from_addr]=max(int(cwnd_dict[from_addr]/2),2)
                            cwnd_dict[from_addr]=1
                            #change state
                            state_dict[from_addr]=1
                            #retransmit the duplicate sequence num packet
                            if duplicate_seq_num* MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                pass
                            else:
                                time_dict[from_addr][duplicate_seq_num]=time.time()
                                left=duplicate_seq_num*MAX_PAYLOAD
                                right=min((duplicate_seq_num+1)*MAX_PAYLOAD,CHUNK_DATA_SIZE)
                                next_data=config.haschunks[ex_sending_chunkhash][left:right]
                                # send loss packet data
                                data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), duplicate_seq_num, 0,0,0)
                                sock.sendto(data_header+next_data, from_addr)

                            # retransmit the packet [Farest,next_sequence_num_dict[from_addr]-1] not yet received ack
                            for sequence_num in range(Farest,min(512,next_sequence_num_dict[from_addr])):
                                if sequence_num not in send_rev_dict[from_addr]:
                                    if sequence_num* MAX_PAYLOAD>=CHUNK_DATA_SIZE:
                                        break
                                    else:
                                        time_dict[from_addr][sequence_num]=time.time()
                                        left=sequence_num*MAX_PAYLOAD
                                        right = min((sequence_num+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                                        next_data = config.haschunks[ex_sending_chunkhash][left: right]
                                        # send next data
                                        data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data), sequence_num, 0,0,0)
                                        sock.sendto(data_header+next_data, from_addr)
                

def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock ,chunkf, outf)
    else:
        pass

def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    global sending_now
    global ex_received_chunk
    global crashed_peer
    count=1
    try:
        while True:
            ready = select.select([sock, sys.stdin],[],[], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready: #receieve
                    process_inbound_udp(sock)
                if sys.stdin in read_ready: #download
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
            count=count+1
            #wait for the package transfer finished
            if count%300000==0: #check receiver whether some whohas or ihave package lost
                for key in ex_received_chunk.keys():
                    if len(ex_downloading_chunkhash[key])!=CHUNK_DATA_SIZE:
                        sock.add_log("whohas or ihave lost")
                        download_hash = bytes()
                        # hex_str to bytes
                        datahash = bytes.fromhex(key)
                        print(f"datahash: {bytes.hex(datahash)}")
                        download_hash = download_hash + datahash
                        # Step2: make WHOHAS pkt
                        whohas_header = struct.pack("!HBBHHIIII", 52305,0, 0, HEADER_LEN, HEADER_LEN+len(download_hash), 0, 0,0,0)
                        whohas_pkt = whohas_header + download_hash
                            # Step3: flooding whohas to all peers in peer list
                        peer_list = config.peers
                        for p in peer_list:
                            if int(p[0]) != config.identity:
                                sock.sendto(whohas_pkt, (p[1], int(p[2])))
            #check sender whether time_out
            for key in sending_now.keys(): 
                #retransmit
                for sequence_num in range(base_num_dict[key] , min(512 , next_sequence_num_dict[key])):
                    if sequence_num not in send_rev_dict[key] and time_out_dict[key] != 0 and time.time() - time_dict[key][sequence_num] > time_out_dict[key]:
                        ssthresh_dict[key]=max(int(cwnd_dict[key]/2),2)
                        cwnd_dict[key]=1
                        if state_dict[key]==2:
                            state_dict[key]=1
                        if  sequence_num*MAX_PAYLOAD>CHUNK_DATA_SIZE:
                                break
                        else:
                            left = sequence_num * MAX_PAYLOAD
                            right = min((sequence_num+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                            next_data = config.haschunks[ex_sending_chunkhash][left: right]
                            # send next data
                            time_dict[key][sequence_num] = time.time()
                            data_header = struct.pack("!HBBHHIIII", 52305,0,  3, HEADER_LEN, HEADER_LEN+len(next_data),sequence_num, 0,0,0)
                            sock.sendto(data_header+next_data, key)    
            #from receiver side check  whether sender crash
            for key in list(receiving_now.keys()):
                hash_str=receiving_now[key]
                # we assume the peer is crashed
                if key in receive_time_dict.keys() and time.time()-receive_time_dict[key]>9 and len(ex_received_chunk[hash_str])!=CHUNK_DATA_SIZE:
                   sock.add_log("find peer crashed")
                   sock.add_log(time.time())
                   #add it to crashed_peer
                   crashed_peer.append(key)
                   #find the chunk received now
                   hash_str=receiving_now[key]
                   #delete all the data received,and receive from another peer
                   ex_received_chunk[hash_str]=bytes()
                   download_hash = bytes()
                   # hex_str to bytes
                   datahash = bytes.fromhex(hash_str)
                   print(f"datahash: {bytes.hex(datahash)}")
                   download_hash = download_hash + datahash
                   # Step2: make WHOHAS pkt
                   whohas_header = struct.pack("!HBBHHIIII", 52305,0, 0, HEADER_LEN, HEADER_LEN+len(download_hash),0,0,0,0)
                   whohas_pkt = whohas_header + download_hash
                   # Step3: flooding whohas to all peers in peer list
                   peer_list = config.peers
                   receiving_now.pop(key)
                   for p in peer_list:
                        if int(p[0]) != config.identity and (p not in crashed_peer):
                            sock.sendto(whohas_pkt, (p[1], int(p[2])))
                            sock.add_log("resend whohas message")

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)