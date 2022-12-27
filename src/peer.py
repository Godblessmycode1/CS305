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

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512*1024
HEADER_LEN = struct.calcsize("HBBHHII")
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
          whohas_header = struct.pack("HBBHHII", socket.htons(52305),35, 0, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(download_hash)), socket.htonl(0), socket.htonl(0))
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
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type,hlen, plen, Seq, Ack= struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        chunkhash_str=bytes.hex(get_chunk_hash)
        #receive the first ihave message from one particular peer
        if chunkhash_str not in receiving_now.values():
            receiving_now[from_addr]=chunkhash_str
            # send back GET pkt
            get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2 , socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
            get_pkt = get_header+get_chunk_hash
            sock.sendto(get_pkt, from_addr)

    elif Type == 3:
        # received a DATA pkt
        ex_downloading_chunkhash=receiving_now[from_addr]
        receiving_now[ex_downloading_chunkhash]=from_addr
        ex_received_chunk[ex_downloading_chunkhash] += data
        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305),35,  4,socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), 0,Seq)
        sock.sendto(ack_pkt, from_addr)
        
        print(f"data len: {len(ex_received_chunk[ex_downloading_chunkhash])} , seq: {socket.ntohl(Seq)} ,downloading chunkhas: {ex_downloading_chunkhash}")
        # see if finished
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            print("finish!")
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)
            # add to this peer's haschunk:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]
            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")
            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}" )
            success = ex_downloading_chunkhash==received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")

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
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(whohas_chunk_hash)), socket.htonl(0), socket.htonl(0))
            ihave_pkt = ihave_header+whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)

    elif Type == 2:
        # received a GET pkt
        # find get_chunk_hash
        get_chunk_hash=data[:20]
        chunkhash_str=bytes.hex(get_chunk_hash)
        # don't reach max send
        if from_addr not in sending_now.keys() and len(sending_now)<config.max_conn:
            sending_now[from_addr]=chunkhash_str
            chunk_data = config.haschunks[chunkhash_str][:MAX_PAYLOAD]
            # send back DATA
            data_header = struct.pack("HBBHHII", socket.htons(52305),35, 3, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(chunk_data)), socket.htonl(0), 0)
            sock.sendto(data_header+chunk_data, from_addr)

        
    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        ex_sending_chunkhash=sending_now[from_addr]
        if (ack_num+1)*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished,remove the receiver address。
            sending_now.pop(from_addr)
            print(f"finished sending {ex_sending_chunkhash}")
            pass
        else:
            left = (ack_num+1) * MAX_PAYLOAD
            right = min((ack_num+2)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(52305),35,  3, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(next_data)), socket.htonl(ack_num+1), 0)
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
