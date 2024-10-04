#!/usr/bin/python3

import os
import ssl
import select
import socket
import logging
import _thread
import argparse
import tempfile

import certmitm.util
import certmitm.certtest
import certmitm.connection


description = r"""
               _             _ _               _                                     
              | |           (_) |             | |                                    
  ___ ___ _ __| |_ _ __ ___  _| |_ _ __ ___   | |__  _   _    __ _  __ _ _ __   ___  
 / __/ _ \ '__| __| '_ ` _ \| | __| '_ ` _ \  | '_ \| | | |  / _` |/ _` | '_ \ / _ \ 
| (_|  __/ |  | |_| | | | | | | |_| | | | | | | |_) | |_| | | (_| | (_| | |_) | (_) |
 \___\___|_|   \__|_| |_| |_|_|\__|_| |_| |_| |_.__/ \__, |  \__,_|\__,_| .__/ \___/ 
                                                      __/ |             | |          
                                                     |___/              |_|          

A tool for testing for certificate validation vulnerabilities of TLS connections made by a client device or an application.

Created by Aapo Oksman - https://github.com/AapoOksman/certmitm - MIT License
"""


# Handle command line flags/arguments
def handle_args():
    parser = argparse.ArgumentParser(description=description, prog="certmitm.py", formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-l', '--listen', nargs=1, help="Listen for a connection", metavar="PORT", type=int, required=True)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbosity', default=False)
    parser.add_argument('-w', '--workdir', nargs=1, help='Set the working directory', metavar="DIRECTORY")
    parser.add_argument('-r', '--retrytests', nargs=1, help="How many times each test is run", default="1")
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug verbosity', default=False)
    parser.add_argument('-s', '--show-data', action="store_true", help="Log the intercepted data to console. Trunkates to a sensible length", default=False)
    parser.add_argument('--instant-mitm', action='store_true', help='Forward intercepted data before all tests are completed', default=False)
    parser.add_argument('--skip-additional-tests', action='store_true', help='Use first successfull test to mitm without trying any others', default=False)
    parser.add_argument('--show-data-all', action="store_true", help="Log all of the intercepted data to console. Not recommended as large amounts of data will mess up your console", default=False)
    # parser.add_argument('--pre-generate', nargs=2, help="Pre-generate server certificates for a specific hostname", metavar=("HOSTNAME", "DIRECTORY"))  # Not yet implemented. Later on this will be a part of a required mutually exclusive group with listen option.
    # parser.add_argument('--upstream-proxy', nargs=1, help="Upstream proxy for MITM. For example, BURP (127.0.0.1:8080)", metavar="ADDRESS")  # Not yet implemented

    return parser.parse_args()


def threaded_connection_handler(downstream_socket: socket.socket) -> None:
    try:
        global connection_tests

        # Lets start by initializing a mitm_connection object with the client connection
        mitm_connection = certmitm.connection.mitm_connection(downstream_socket, logger)
        connection = certmitm.connection.connection(mitm_connection.downstream_socket, logger)
        logger.debug(f"got connection: {connection.to_str()}")

        # Lets get a test for the client
        test = connection_tests.get_test(connection)
        if not test:
            # No tests available, lets just do a TCP mitm :(
            logger.debug(f"Can't mitm {connection.identifier}. Forwarding plain tcp")
            try:
                mitm_connection.set_upstream(connection.upstream_ip, connection.upstream_port)
            except OSError:
                logger.debug(f"Can't connect to {connection.identifier}")
                return
        else:
            # We have a test to run
            logger.debug(f"next test is: {test.to_str()}")
            try:
                # Lets try to wrap the client connection to TLS
                mitm_connection.wrap_downstream(test.context)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError) as e:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = {e}")
                return
            mitm_connection.set_upstream(connection.upstream_ip, connection.upstream_port)
            if mitm_connection.upstream_socket:
                try:
                    mitm_connection.wrap_upstream(connection.upstream_sni)
                except (ssl.SSLZeroReturnError, TimeoutError):
                    logger.debug("Cannot wrap upstream socket. Destroying also the TCP socket.")
                    mitm_connection.upstream_socket = None
            if not mitm_connection.upstream_socket:
                logger.info(f"Cannot connect to {connection.upstream_ip}: with TLS, still trying to intercept without mitm.")

        from_client = None
        from_server = None
        insecure_data = b""
        logged_insecure = False

        if test:
            mitm = test.mitm
        else:
            mitm = True

        logger.debug(f"mitm {mitm}")
        count = 0

        # Lets mitm, The upstream and downstream might be either TLS or TCP
        try:
            while count < 5:
                count += 1
                logger.debug(f"count {count}")
                # Lets see if the client or the server wants to talk to us
                if mitm_connection.upstream_socket:
                    ready = select.select([mitm_connection.downstream_socket, mitm_connection.upstream_socket], [], [], 1)
                else:
                    if mitm_connection.downstream_tls:
                        # Only do one party mitm if we're trying to intercept TLS
                        logger.debug("Connecting only to the client and not upstream")
                        ready = select.select([mitm_connection.downstream_socket], [], [], 1)
                    else:
                        logger.debug("Could not connect to upstream on TCP mitm")
                        return

                for ready_socket in ready[0]:
                    logger.debug(ready_socket)
                    if ready_socket == mitm_connection.downstream_socket:
                        # Lets read data from the client
                        try:
                            from_client = mitm_connection.downstream_socket.recv(4096)
                        except TimeoutError:
                            count = 5
                            break
                        logger.debug(f"client: {from_client}")
                        if from_client == b'':
                            count = 5
                            break
                        if from_client and mitm_connection.downstream_tls:
                            # double check that we're not logging the TLS handshake
                            if not certmitm.util.SNIFromHello(from_client):
                                if not mitm:
                                    if not logged_insecure:
                                        # Insecure connection! GG happy bounties, Lets log this and add the tests to successfull test list for future mitm
                                        logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = data intercepted!")
                                        connection_tests.add_successfull_test(connection, test)
                                        logged_insecure = True
                                    insecure_data += from_client
                                connection_tests.log(connection, 'client', from_client)

                        if from_client and not mitm and not args.instant_mitm: 
                            # If we don't have instant mitm, lets not send anything to server
                            logger.debug("not sending to upstream when not mitm")
                        else:
                            if mitm_connection.upstream_socket:
                                mitm_connection.upstream_socket.send(from_client)
                                logger.debug(f"sending to server: {from_client}")
                        count = 0
                    elif ready_socket == mitm_connection.upstream_socket:
                        # Lets read data from the server
                        try:
                            from_server = mitm_connection.upstream_socket.recv(4096)
                        except TimeoutError:
                            count = 1
                            from_server = b''
                        logger.debug(f"server: {from_server}")
                        if from_server and mitm_connection.upstream_tls:
                            if not mitm:
                                insecure_data += from_server
                            connection_tests.log(connection, 'server', from_server)
                        if from_server == b'':
                            if mitm or args.instant_mitm:
                                break
                            else:
                                logger.debug("not sending b'' to client when not in mitm")
                                continue
                        else:
                            count = 0
                        mitm_connection.downstream_socket.send(from_server)
                        logger.debug(f"sending to client: {from_server}")
                    else:
                        # We should never arrive here
                        logger.exception("Select returned unknown connection")
                else:
                    continue
                break
            else:
                logger.debug("mitm timeout")
        except (ConnectionResetError, ssl.SSLEOFError, TimeoutError):
            # We might get this depending on the TLS implementation
            if mitm_connection.downstream_tls and not insecure_data:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = Nothing received, someone closed connection")
        except Exception as e:
            # Something unexpected happened
            logger.exception(e)
        finally:
            logger.debug("finally")
            # Log insecure data
            if insecure_data:
                if args.show_data_all:
                    logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} intercepted data = '{insecure_data}'")
                elif args.show_data:
                    logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} intercepted data = '{insecure_data[:2048]}'")
            # Log secure connections
            elif mitm_connection.downstream_tls and not mitm:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = Nothing received")

            try:
                # Close TLS gracefully
                mitm_connection.downstream_socket.unwrap()
                mitm_connection.upstream_socket.unwrap()
            except ValueError:  # https://github.com/pypa/ssl/blob/53b55dcb92c03edec70690d3cd9177b4c7f16f7b/ssl/__init__.py#L242
                pass
            # Close TCP gracefully
            mitm_connection.downstream_socket.close()
            if mitm_connection.upstream_socket:
                mitm_connection.upstream_socket.close()
            
    except Exception as e:
        # Something really unexpected happened
        logger.exception(e)


def listen_forking(port: int):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(5)

    while True:
        try:
            Client, address = listener.accept()
            Client.settimeout(30)
            logger.debug(f"Request from: {address}")
            _thread.start_new_thread(threaded_connection_handler, (Client, ))
        except Exception as e:
            logger.exception(f"Error in starting thread: {e}")


if __name__ == '__main__':
    args = handle_args()

    logger = certmitm.util.createLogger("log")

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    if args.workdir:
        working_dir = args.workdir[0]
    else:
        working_dir = tempfile.mkdtemp()
    if not os.path.exists(working_dir):
        os.mkdir(working_dir)

    connection_tests = certmitm.connection.connection_tests(logger, working_dir, args.retrytests[0], args.skip_additional_tests)

    if args.listen is not None:
        listen_forking(args.listen[0])
