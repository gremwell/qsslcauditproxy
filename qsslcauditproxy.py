#/usr/bin/env python3
'''
Proxy wrapper for qsslcaudit (https://github.com/gremwell/qsslcaudit).

Author: Sean de Regge (sean@gremwell.com)
'''
__author__  = "Sean de Regge"
__email__   = "sean@gremwell.com"
__version__ = "0.0.1"
from socket import AF_INET, SOCK_STREAM, socket, SOL_SOCKET, SO_REUSEADDR
from subprocess import call
from time import sleep
import argparse
import curses
import itertools
import re
import _thread

TEST_COUNT = 22 # 22 tests to performed with qsslcaudit default settings
HEADER = r"""
=====================================
        Qsslcauditproxy v{}
  {} ({})
=====================================
""".format(__version__, __author__, __email__)

class Host:
    '''
    Represents a host to be tested.
    '''
    id_iter = itertools.count()
    def __init__(self, hostname, blacklist):
        '''
        Consructor.

        @Args:
            hostname(str): server hostname
            blacklist(list): list of blacklisted domains

        @Returns:
            None
        '''
        self.percentage = 0
        self.scanned = False
        self.blacklisted = bool(sum([bhost in hostname for bhost in blacklist]))
        self.hostname = hostname
        self._id = next(self.id_iter)
        self.qsslcauditport = 8443 + self._id

class OutputFactory:
    '''
    ncurses output factory.
    '''
    def __init__(self, ongoing_hosts, screen):
        self.ongoing_hosts = ongoing_hosts
        self.screen = screen
        self.screen.clear()
        self.screen.nodelay(1)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        self.screen.addstr(HEADER)
        self.screen.addstr("Listening for incoming connections to Proxy\n")
        self.screen.refresh()

    def updated_output(self):
        """
        Update ncurse output.
        """
        self.screen.clear()
        self.screen.addstr(self.header)
        # enum dict and write output
        for host in self.ongoing_hosts:
            try:
                if host.scanned:
                    self.screen.addstr("\n[" + str(host.id) + "]Testing " +\
                        host.hostname + " " + str(host.percentage) +\
                        "% done", curses.color_pair(2))
                elif host.blacklisted:
                    self.screen.addstr("\n[" + str(host.id) + "]Skipped " +\
                        host.hostname + " (BLACKLISTED)", curses.color_pair(3))
                else:
                    self.screen.addstr("\n[" + str(host.id) + "]Testing " +\
                        host.hostname + " " + str(host.percentage) +\
                        "% done", curses.color_pair(1))
            except curses.error:
                pass
        self.screen.refresh()

def get_args():
    '''
    Utility function that get command-line arguments using argparse.

    @Args:
        None

    @Returns:
        args(object): argument object
        commandline_options(str): qsslcaudit commandline
    '''
    print(HEADER)
    parser = argparse.ArgumentParser(
        description="A proxy wrapper for Qsslcaudit "\
            "(https://github.com/gremwell/qsslcaudit)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--blacklist',
        help='Blacklist file that holds hosts to exclude from testing,'\
                ' for example known endpoints used by the OS',
        required=False
    )
    parser.add_argument(
        '-p',
        help='Port for proxy to listen on',
        required=False,
        default=8888
    )
    args, commandline_options = parser.parse_known_args()
    return args, commandline_options


def parse_connect(request):
    """
    Parse received HTTP CONNECT requests.

    @Args:
        request(str): HTTP request string
    @Returns:
        host(str): hostname
        port(str): TCP port
    """
    c_index = request.index("CONNECT")
    if c_index == -1:
        print("Error parsing CONNECT request")
        return -1
    port_index = request.index(":")
    host = request[c_index+8:port_index]

    #get port
    http_index = request.index("HTTP/")
    port = request[port_index+1:http_index-1]
    return host, port

def parse_http_request(request):
    """
    Parse received HTTP requests.
    @Args:
        request(str): HTTP request string
    @Returns:
        host(str): hostname
        port(int): always 80
    """
    start_host = request.index(" http://")
    port = 80
    request = request[start_host+8:]
    host = request[:request.index("/")]
    return host, port

def is_valid_hostname(hostname):
    """
    Check whether a hostname is RFC compliant.

    @Args:
        hostname(str): remote server hostname
    @Returns:
        valid(bool): True if valid, False otherwise
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def run_qsslcaudit(host, commandline_options):
    """
    Launch a qsslcaudit subprocess.

    @Args:
        host(str): server hostname for which we check connections
        commandline_options(str): custom qsslcaudit command line options
    @Returns
        None
    """
    global TEST_COUNT
    if not is_valid_hostname(host.hostname):
        return
    cmdline = 'qsslcaudit -l 0.0.0.0 -p ' + str(host.qsslcauditport) + " "
    for cmd_option in commandline_options:
        cmdline += cmd_option + " "
    cmdline += '--user-cn ' + host.hostname + ' > ' + host.hostname + ".txt"
    call(cmdline, shell=True)
    #when this finishes, test is complete
    #calibrate percentages based on actual TEST_COUNT, which is dependant on qsslcaudit settings
    TEST_COUNT = TEST_COUNT * (host.percentage / 100)
    host.percentage = 100
    host.scanned = True

def proxy_client_server(clientsock, server_address, initial_data):
    """
    Setup proxy listener.

    @Args:
        clientsock(): client socket
        server_address(tuple): tuple (hostname, port)
        initial_data(str): initial request data
    @Returns:
        None
    """
    dstsock = socket(AF_INET, SOCK_STREAM)
    try:
        dstsock.connect(server_address)
    except:
        return
    if dstsock is None:
        return
        # nonblocking sockets that proxy all requests
    if initial_data:
        dstsock.send((initial_data).encode('utf-8'))
    while 1:
        clientsock.setblocking(0)
        dstsock.setblocking(0)
        try:
            data = clientsock.recv(50000)
            if not data:
                dstsock.close()
                clientsock.close()
                break
            dstsock.send(data)
        except:
            pass
        try:
            data = dstsock.recv(50000)
            if not data:
                dstsock.close()
                clientsock.close()
                break
            clientsock.send(data)
        except:
            pass
    clientsock.close()
    dstsock.close()
    return


def handler(clientsock, blacklist, output_factory, ongoing_hosts, commandline_options):
    """
    Main handler.

    @Args:
        clientsock(): sock receiver.
        blacklist(list): list of blacklisted domains.
        ongoing_hosts(list): list of currently checked hosts.
        commandline_options(str): custom qsslcaudit command line options
    @Returns:
        None
    """
    rawdata = clientsock.recv(50000)
    if not rawdata:
        return
    data = str(rawdata)
    if data.find("CONNECT") == -1:
        data = str(rawdata, 'utf-8')
        #no CONNECT so it must be plain HTTP request
        dsthost, dstport = parse_http_request(data)
        #proxy to host
        server_address = (dsthost, int(dstport))
        proxy_client_server(clientsock, server_address, data)
        return
    #it is a CONNECT request
    dsthost, dstport = parse_connect(data)
    clientsock.send(("HTTP/1.1 200 Connection Established\r\n\r\n").encode('utf-8'))
    #check if handled already, otherwise create new host object
    host = None
    for ongoing_host in ongoing_hosts:
        if ongoing_host.hostname == dsthost:
            host = ongoing_host
    #if the host is not yet created, create now object and start qsslcaudit thread for the host
    if host is None:
        host = Host(dsthost, blacklist)
        ongoing_hosts.append(host)
        if not host.blacklisted:
            _thread.start_new_thread(run_qsslcaudit, (host, commandline_options))
            sleep(2)  # qsslcaudit needs some time

    #if scan is not completed, redirect traffic to qsslcaudit instance
    if host.scanned or host.blacklisted:
        server_address = (dsthost, int(dstport))
    else:
        server_address = ("localhost", int(host.qsslcauditport))
        host.percentage += int(100 / TEST_COUNT)
    output_factory.updated_output()
    proxy_client_server(clientsock, server_address, None)

#if __name__ == '__main__':
def main(screen, args, commandline_options):
    """
    Main function.

    @Args:
        screen(): ncurse screen
        args(object): argparse object
        commandline_options(str): custom qsslcaudit command line options
    @Returns:
        None
    """
    addr = ("", int(args.p))
    serversock = socket(AF_INET, SOCK_STREAM)
    serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serversock.bind(addr)
    serversock.listen(200)

    blacklist = []
    if args.blacklist:
        with open(args.blacklist, 'r') as f:
            blacklist = [line.strip() for line in f.readlines()]

    print("[+]Proxy listening for incoming connections on", args.p)
    ongoing_hosts = list()
    outputfactory = OutputFactory(ongoing_hosts, screen)
    while 1:
        clientsock, addr = serversock.accept()
        _thread.start_new_thread(
            handler,
            (
                clientsock,
                blacklist,
                outputfactory,
                ongoing_hosts,
                commandline_options
            )
        )

try:
    args, commandline_options = get_args()
    curses.wrapper(main, args, commandline_options)
except KeyboardInterrupt:
    print("User Exited")
