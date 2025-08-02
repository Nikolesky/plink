import socket
import threading
import random
import os
import json
from multiprocessing import Process, Manager, cpu_count
from utils.logging import log, LogType
from backend.cryptography.data.sender.chunk_manager import yield_chunks
from backend.cryptography.data.receiver.chunk_manager import collect_chunks_parallel, join_chunks
from backend.cryptography.data.sender.compression import compress_file
from backend.cryptography.data.receiver.compression import decompress_final_chunk
from backend.cryptography.data.sender.metadata import retrieve_metadata as retrieve_sender_metadata
from backend.cryptography.core.cipher import encryption, decryption

"""
example for dictionary of self_info and peer_info (network metadata) :-
{
    "network_type": "NAT",
    "nat_type": "Symmetric NAT",
    "upnp_enabled": False,
    "external_ip": "152.59.21.64",
    "local_ip": "192.168.231.112",
    "firewall_enabled": True,
    "open_ports": [80, 900, 800, 443, ...]  # total of 64 ports
}

APPROACH:
--------
first restricted cone sends a dummy packet to symmetric NAT
the dummy packet is not recieved by the symmetric NAT but the symmetric NAT gets the IP of the restricted cone
then the symmetric cone sends a dummy packet to restricted cone
the restricted cone recieves the dummy packet and a connection is established

--------
"""


class RC_to_SC:
    def __init__(self, self_info, peer_info, self_private_key, peer_public_key, log_path):
        self.public_ip = self_info["external_ip"]
        self.public_port = self_info["open_ports"][0]

        self.peer_ip = peer_info["external_ip"]
        self.peer_port = peer_info["open_ports"][0] 

        # Cryptographic keys
        self.private_key = self_private_key
        self.public_key = peer_public_key

        # System and logging configuration
        self.log_path = log_path
        self.worker_count = min(cpu_count() * 2, len(self.self_ports))
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self.public_port))

        if self.NAT_type == "Restricted Cone NAT":
            print(f"[Restricted] Bound to {self.public_ip}:{self.public_port}")
            print(f"[Restricted] Will send dummy to Symmetric NAT at {self.peer_ip}:<random_port>")
        elif self.NAT_type == "Symmetric NAT":
            print(f"[Symmetric] Bound to {self.public_ip}:{self.public_port}")
            print(f"[Symmetric] Will send dummy to Restricted NAT at {self.peer_ip}:{self.peer_port}")

        log("Session initialized. Control channel established.", general_logfile_path=self.log_path)
        
    def punch_and_listen_RestrictedCone(self):
        def recv_loop():
            while True:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    print(f"[Restricted] Received from {addr}: {data}")
                except Exception as e:
                    print(f"[Restricted] Error: {e}")
                    break

        threading.Thread(target=recv_loop, daemon=True).start()

        dummy_port = random.randint(10000, 60000)
        self.sock.sendto(b"dummy", (self.peer_ip, dummy_port))
        print(f"[Restricted] Sent dummy to {self.peer_ip}:{dummy_port}")

    def punch_and_listen_SymmetricCone(self):
        def recv_loop():
            while True:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    print(f"[Symmetric] Received from {addr}: {data}")
                except Exception as e:
                    print(f"[Symmetric] Error: {e}")
                    break

        threading.Thread(target=recv_loop, daemon=True).start()

        self.sock.sendto(b"dummy", (self.peer_ip, self.peer_port))
        print(f"[Symmetric] Sent dummy to {self.peer_ip}:{self.peer_port}")

    # --------------------------------------------------- #
    #                     SENDING LOGIC                   #
    # --------------------------------------------------- #
    def send(self, filepath, chunk_size=8192):
        """
        Coordinates the entire file sending process.

        1. Compresses the file.
        2. Generates and encrypts the file metadata.
        3. Sends metadata over the control channel and waits for acknowledgment.
        4. Upon acknowledgment, starts the parallel transfer of file data.
        """
        # --- Stage 1: File Preparation & Metadata Exchange ---
        if not os.path.isfile(filepath):
            log(f"File not found: {filepath}", LogType.CRITICAL, "Failure", self.log_path)
            return

        temp_dir = f"temp_sender_{os.getpid()}"
        os.makedirs(temp_dir, exist_ok=True)
        compressed_path = compress_file(filepath, temp_dir, self.log_path)
        log(f"File compressed to {compressed_path}", general_logfile_path=self.log_path)

        metadata = retrieve_sender_metadata(
            file_path=str(compressed_path),
            chunk_size=chunk_size,
            public_ip=self.self_ip,
            ports=self.self_ports,
            general_logfile_path=self.log_path
        )
        encrypted_metadata = encryption(metadata, self.public_key, self.log_path)

        # --- Stage 2: Control Channel Communication ---
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('', self.control_port_self))
                log("Sending file metadata. Awaiting confirmation from receiver...", general_logfile_path=self.log_path)
                sock.sendto(b"[META_START]" + json.dumps(encrypted_metadata).encode() + b"[META_END]", (self.peer_ip, self.control_port_peer))

                sock.settimeout(60.0) # Wait up to 60 seconds for the receiver's 'OK'
                ack, _ = sock.recvfrom(1024)
                if ack != b'META_OK':
                    raise ConnectionAbortedError("Receiver sent an invalid acknowledgment.")
                log("Receiver confirmed metadata. Starting data transfer.", status="Success", general_logfile_path=self.log_path)
        except Exception as e:
            log(f"Metadata exchange failed: {e}", LogType.CRITICAL, "Failure", self.log_path)
            return

        # --- Stage 3: Parallel Data Transfer ---
        self._punch_hole(self.data_ports_self, self.data_ports_peer)

        all_chunks = list(yield_chunks(compressed_path, chunk_size, self.log_path))

        # Distribute chunks among worker processes
        processes = []
        for i in range(self.worker_count):
            worker_chunks = all_chunks[i::self.worker_count]
            p = Process(target=self._send_worker, args=(worker_chunks,))
            processes.append(p)
            p.start()

        for p in processes:
            p.join()

        log("File data sent successfully.", status="Success", general_logfile_path=self.log_path)
        os.remove(compressed_path)
        os.rmdir(temp_dir)

    def _send_worker(self, chunks):
        """A worker process that sends an assigned list of chunks over the data ports."""
        with Manager() as manager:
            sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in self.data_ports_self]
            for i, sock in enumerate(sockets):
                sock.bind(('', self.data_ports_self[i]))

            for i, (chunk_num, chunk_data) in enumerate(chunks):
                header = f"[{chunk_num}]".encode()
                sock_index = i % len(sockets) # Round-robin socket usage
                sockets[sock_index].sendto(header + chunk_data, (self.peer_ip, self.data_ports_peer[sock_index]))

            for sock in sockets:
                sock.close()

    # --------------------------------------------------- #
    #                    RECEIVING LOGIC                  #
    # --------------------------------------------------- #
    def recv(self, output_path="received_file", chunk_size=8192):
        """
        Coordinates the entire file receiving process.

        1. Listens on the control channel for file metadata.
        2. Decrypts metadata; if successful, sends an acknowledgment.
        3. Listens on all data ports in parallel for the file chunks.
        4. Reassembles and decompresses the file.
        """
        # --- Stage 1: Control Channel Communication ---
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('', self.control_port_self))
                sock.settimeout(300.0) # Wait up to 5 minutes for a transfer to start
                log("Ready to receive. Listening for incoming metadata...", general_logfile_path=self.log_path)
                data, peer_addr = sock.recvfrom(4096)

                if not data.startswith(b"[META_START]"):
                    raise ValueError("Received invalid metadata format.")

                metadata_raw = data.split(b"[META_START]")[1].split(b"[META_END]")[0]
                metadata = decryption(json.loads(metadata_raw.decode()), self.private_key, self.log_path)
                log(f"Metadata decrypted successfully: {metadata}", general_logfile_path=self.log_path)

                # Acknowledge successful decryption to start the transfer
                sock.sendto(b'META_OK', (self.peer_ip, self.control_port_peer))
        except Exception as e:
            log(f"Failed to receive or decrypt metadata: {e}", LogType.CRITICAL, "Failure", self.log_path)
            return

        # --- Stage 2: Parallel Data Reception ---
        temp_dir = f"temp_receiver_{os.getpid()}"
        os.makedirs(temp_dir, exist_ok=True)

        with Manager() as manager:
            received_chunks = manager.list()
            total_chunks = metadata.get("total_chunks")

            processes = []
            for i in range(self.worker_count):
                p = Process(target=self._recv_worker, args=(received_chunks, total_chunks))
                processes.append(p)
                p.start()

            for p in processes:
                p.join()

            # --- Stage 3: Reassembly and Cleanup ---
            if len(received_chunks) != total_chunks:
                log(f"Incomplete transfer: Got {len(received_chunks)} of {total_chunks} chunks.", LogType.ERROR, "Failure", self.log_path)
            else:
                log("All chunks received. Reassembling file.", status="Success", general_logfile_path=self.log_path)

            chunk_logfile = os.path.join(temp_dir, "chunks.json")
            collect_chunks_parallel(list(received_chunks), chunk_logfile, self.log_path, temp_dir)
            joined_path = join_chunks(temp_dir, chunk_logfile, self.log_path, chunk_size=chunk_size)
            decompress_final_chunk(joined_path, output_path, self.log_path)
            log(f"File successfully saved to {output_path}", status="Success", general_logfile_path=self.log_path)

        os.remove(chunk_logfile)
        os.rmdir(temp_dir)

    def _recv_worker(self, received_chunks, total_chunks):
        """A worker process that listens on assigned ports and collects chunks."""
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in self.data_ports_self]
        for i, sock in enumerate(sockets):
            sock.bind(('', self.data_ports_self[i]))
            sock.settimeout(45)

        while len(received_chunks) < total_chunks:
            for sock in sockets:
                try:
                    data, _ = sock.recvfrom(8192 + 100)
                    header_end = data.find(b"]")
                    chunk_num = int(data[1:header_end])
                    chunk_data = data[header_end + 1:]
                    received_chunks.append((chunk_data, chunk_num))
                except socket.timeout:
                    continue
                except (ValueError, IndexError):
                    continue

        for sock in sockets:
            sock.close()
