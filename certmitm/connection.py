import certmitm.util
import certmitm.certtest
import socket
import threading
import time
import os
import json

def counter():
    i = 0
    while True:
        yield i
        i += 1

connection_counter = counter()

class connection(object):

    def __init__(self, client_socket, logger):
        self.id = next(connection_counter)
        self.timestamp = time.time()
        self.lock = threading.Lock()
        self.logger = logger
        self.client_socket = client_socket
        self.client_name = str(client_socket.getpeername())
        self.client_ip = self.client_name.split("'")[1]
        self.client_port = int(self.client_name.split(" ")[1].split(')')[0]) #Dirty I know :)
        self.upstream_ip, self.upstream_port = certmitm.util.sock_to_dest(self.client_socket)
        if self.upstream_ip == "127.0.0.1" and self.upstream_port == 9900:
            self.logger.debug(f"Setting debug upstream")
            self.upstream_port = 10000
        try:
            self.upstream_sni = certmitm.util.SNIFromHello(self.client_socket.recv(4096, socket.MSG_PEEK))
        except (TimeoutError, ConnectionResetError):
            self.upstream_sni = None
        if self.upstream_sni:
            self.upstream_name = self.upstream_sni
        else:
            self.upstream_name = self.upstream_ip
        self.upstream_str = f"{self.upstream_ip}:{self.upstream_port}:{self.upstream_sni}"
        self.identifier = str([self.client_ip, self.upstream_name, self.upstream_port])

    def to_str(self):
        return f"ID: {self.id}, Client: {self.client_ip}:{self.client_port}, Upstream: {self.upstream_ip}:{self.upstream_port} '{self.upstream_sni}', Identifier: {self.identifier}"

class connection_tests(object):

    def __init__(self, logger, working_dir, retrytests, skiptests):
        self.all_test_dict = {}
        self.current_test_dict = {}
        self.lock = threading.Lock()
        self.logger = logger
        self.working_dir = working_dir
        self.retrytests = retrytests
        self.skiptests = skiptests

    def log(self, connection, who, what):
        self.all_test_dict[connection.identifier].log(connection.timestamp, who, what)

    def get_test(self, connection):
        # If the connection is first of its kind
        if connection.identifier not in self.all_test_dict.keys():
            with self.lock:
                if connection.identifier not in self.all_test_dict.keys():
                    # Create a dict to store tests for the connection identifier 
                    self.all_test_dict[connection.identifier] = certmitm.connection.test_list(connection, self.logger, self.working_dir, self.retrytests, self.skiptests)
                    self.logger.debug(f"Created a test dict: '{self.all_test_dict[connection.identifier].to_str()}'")


        # Get next test based on the connection identifier
        next_test = self.all_test_dict[connection.identifier].get_test()
        if next_test:
            self.current_test_dict[connection.client_name] = next_test
            return next_test

        return None

    def add_successfull_test(self, connection, test):
        self.all_test_dict[connection.identifier].add_successfull_test(test)
        self.logger.debug(f"Succesfull test list now: {self.all_test_dict[connection.identifier].successfull_test_list}")

class test_list(object):

    def __init__(self, connection, logger, working_dir, retrytests, skiptests):
        self.connection = connection
        self.lock = threading.Lock()
        self.test_list = None
        self.successfull_test_list = []
        self.logger = logger
        self.working_dir = working_dir
        self.retrytests = retrytests
        self.skiptests = skiptests
        self.errorpath = os.path.join(self.working_dir,self.connection.client_ip)
        self.mitmdatadir = os.path.join(self.errorpath,self.connection.upstream_name,"data")
        self.certpath = os.path.join(self.errorpath,self.connection.upstream_name,"certs")

    def log(self, timestamp, who, what):
        txtfilename = os.path.join(self.mitmdatadir,f'{timestamp}.txt')
        binfilename = os.path.join(self.mitmdatadir,f'{timestamp}.bin')
        dirname = os.path.dirname(txtfilename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(txtfilename, 'a') as txtmitmfile:
            with open(binfilename, 'ab') as binmitmfile:
                jsondata = json.dumps({"timestamp":str(time.time()), "from":str(who), "data":str(what)})
                txtmitmfile.write(f'{jsondata}\n')
                binmitmfile.write(what)

    def get_test(self):
        # If the tests have not yet been generated
        if self.test_list == None:
            with self.lock:
                if not self.test_list:
                    # Get upstream fullchain from the server
                    self.logger.debug(f"New connection to {self.connection.upstream_str}")
                    self.upstream_cert_fullchain = certmitm.util.get_server_cert_fullchain(self.connection.upstream_ip, self.connection.upstream_port, self.connection.upstream_sni)
                    self.logger.debug(f"{self.connection.upstream_str} fullchain: '{self.upstream_cert_fullchain}'")
                    # Initialize test list
                    self.test_list = []
                    # Generate list of tests for the 
                    for test in certmitm.certtest.generate_test_context(self.upstream_cert_fullchain, self.connection.upstream_sni or self.connection.upstream_ip, self.working_dir, self.logger):
                        for i in range(int(self.retrytests)):
                            self.test_list.append(test)
                    self.logger.debug(f"Generated tests: '{self.test_list}' to {self.connection.upstream_str}")

        # Pop next test if were are not skipping tests
        if not (self.successfull_test_list != [] and self.skiptests):
            if self.test_list:
                with self.lock:
                    if self.test_list != []:
                        return self.test_list.pop(0)

        # Get first successfull test
        if self.successfull_test_list != []:
            test = self.successfull_test_list[0]
            test.mitm = True
            return test

        # tests ran out an no successfull ones found
        return None

    def add_successfull_test(self, test):
        self.successfull_test_list.append(test)

        # Copy successfull test certs to mitmcerts
        if not os.path.exists(self.certpath):
            os.makedirs(self.certpath)
        certfilepath = os.path.join(self.certpath,f'{test.name}_cert.pem')
        keyfilepath = os.path.join(self.certpath,f'{test.name}_key.pem')
        with open(test.certfile, 'rb') as certfile:
            with open(certfilepath, 'wb') as newcertfile:
                newcertfile.write(certfile.read())
        with open(test.keyfile, 'rb') as keyfile:
            with open(keyfilepath, 'wb') as newkeyfile:
                newkeyfile.write(keyfile.read())

        # Log error to errors.txt
        filename = os.path.join(self.errorpath,'errors.txt')
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, 'a') as errorfile:
            jsondata = json.dumps({"timestamp":str(time.time()),"client":self.connection.client_ip ,"destination":{"name":self.connection.upstream_name,"ip":self.connection.upstream_ip,"port":self.connection.upstream_port,"sni":self.connection.upstream_sni},"testcase":test.name,"certfile":certfilepath,"keyfile":keyfilepath,"datapath":self.mitmdatadir})
            errorfile.write(f"{jsondata}\n")

    def to_str(self):
        return(f"Identifier: {self.connection.identifier}, Upstream: {self.connection.upstream_str}, Remaining tests: {self.test_list}, Successfull tests {self.successfull_test_list}")

class mitm_connection(object):

    def __init__(self, downstream_socket, logger):
        self.logger = logger
        self.downstream_socket = downstream_socket
        self.downstream_socket.settimeout(10)
        self.downstream_tls = False
        self.downstream_tls_buf = b""

    def set_upstream(self, ip, port):
        self.logger.debug(f"connecting to TCP upstream")
        self.upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream_socket.settimeout(10)
        try:
            self.upstream_socket.connect((ip, port))
            self.upstream_tls = False
            self.logger.debug(f"connected to TCP upstream")
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            self.logger.debug(f"Upstream connection failed with {e}")
            self.upstream_socket = None

    def wrap_downstream(self, context):
        self.logger.debug(f"Wrapping downstream with TLS")
        self.downstream_socket = context.wrap_socket(self.downstream_socket, server_side=True)
        self.downstream_socket.settimeout(10)
        self.downstream_tls = True
        self.logger.debug(f"Wrapped downstream with TLS")

    def wrap_upstream(self, hostname):
        self.logger.debug(f"Wrapping upstream with TLS")
        self.upstream_context = certmitm.util.create_client_context()
        self.upstream_socket = self.upstream_context.wrap_socket(self.upstream_socket, server_hostname=hostname)
        self.upstream_socket.settimeout(10)
        self.upstream_tls = True
        self.logger.debug(f"Wrapped upstream with TLS")
