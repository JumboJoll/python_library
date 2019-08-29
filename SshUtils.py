#
# Custom wrapper for paramiko ssh library
#

import paramiko
import time
import socket
import logging

#
# Class wrapper which is used to handle ssh
# Note: this class defines an internal target then tries to connect 
#       to that target so that each ssh call does not require respecifiying the ip (or user in some cases)
#
class SshHandler:
    # initialize the class (requires target ip)
    # loads known_hosts, and local ssh keys from ssh_path if specified
    def __init__(self, ip, user = None, port = 22, ssh_path = None, req_host_key = False):
        
        self.setSSHTarget(ip, user, port)
        self.req_host_key = req_host_key
        self.client = paramiko.SSHClient()
        self.ssh_output = None
        self.ssh_error = None
        self.isConnected = False
        if ssh_path is not None:
            self.known_hosts_path = ssh_path + '/known_hosts'

            try:
                self.pkey = paramiko.RSAKey.from_private_key_file(ssh_path + '/id_rsa')
                logging.info('Successfully loaded private key')
            except:
                logging.warning('Private key could not be loaded from: ' + ssh_path + '/id_rsa')
                self.pkey = None

            try:
                with open(ssh_path + '/id_rsa.pub') as pubkeyfile:
                    self.pubkey = pubkeyfile.read()
            except:
                logging.warning('Exception opening: ' + ssh_path + '/id_rsa.pub')
                self.pubkey = None
        else:
            self.known_hosts_path = None
            self.pkey = None
            self.pubkey = None

    # private function used to execute one line (assumes a connection exists)
    def __executeLine(self, line, delay = .2):
        try: 
            logging.info('Executing: ' + line)
            stdin, stdout, stderr = self.client.exec_command(line,timeout=10)
            self.ssh_output = stdout.read()
            self.ssh_error = stderr.read()
            time.sleep(delay)
            if self.ssh_error:
                logging.warning('Problem occurred while running: '+ line + ' The error is ' + str(self.ssh_error))
                result_flag = False
            else:    
                logging.info('Command execution completed successfully ' + line)
                result_flag = True
        except socket.timeout as e:
            logging.error(line + ": has caused the connection to time out")
            self.client.close()
            self.isConnected = False
            result_flag = False
        except Exception as e:
            logging.error(f'Exception while executing command {line} : {e}')
            self.client.close()
            self.isConnected = False
            result_flag = False
        return result_flag

    # Function used to manually try to establish an ssh connetion with target
    # uses internal user if not passed, uses ssh keys then passwd in that order
    def connect(self, user = None, passwd = None):
        if not user is None:
            self.user = user
            
        if self.known_hosts_path is not None:
            try:
                self.client.load_host_keys(self.known_hosts_path)
                logging.info('Successfully loaded known host keys')
            except IOError as e: 
                logging.warning('Unable to load known host keys')

        if not self.req_host_key:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for tries in range(3):
            try:
                self.client.connect(hostname = self.ip, port = self.port, username = self.user, password = passwd, 
                                    pkey = self.pkey, look_for_keys = False) #allow_agent = False,
                logging.info('Connected to host: ' + self.ip)
                result_flag = True
            except paramiko.AuthenticationException as authException:
                logging.error('Authentication failed')
                logging.error(f'PARAMIKO SAYS: {authException}')
                result_flag = False
            except paramiko.SSHException as sshException:
                logging.error('Could not establish SSH connection: %s' % sshException)
                logging.error('Retrying on try: ' + str(tries))
                time.sleep(.1) # wait for .1 sec to retry
                result_flag = False
                continue
            except socket.timeout as e:
                logging.error('Connection timed out')
                result_flag = False
            except Exception as e:
                logging.error('\nException in connecting to the server')
                logging.error('PYTHON SAYS: %s' % e)
                result_flag = False
                self.client.close()
            break
        self.isConnected = result_flag
        return result_flag   

    # Closes connection
    def close(self):
        self.client.close()
        self.isConnected = False

    # Installs public key into the connected user's .ssh/authorized_keys file
    def installPublicKey(self, passwd=None):
        if self.pubkey is not None:
            cmds = ['mkdir -p ~/.ssh/', 
                    'echo "%s" >> ~/.ssh/authorized_keys' % self.pubkey, 
                    'chmod 644 ~/.ssh/authorized_keys',
                    'chmod 700 ~/.ssh/']
            result_flag = self.execute(cmds, passwd=passwd)
        else:
            result_flag = False
    
        if result_flag:
            logging.info('Successfuly installed public key to server: ' + self.ip)
        else:
            logging.error('Something went wrong while trying to install key to server: ' + self.ip)

        return result_flag
    
    # Function used to manually set the ssh target after instantiation
    def setSSHTarget(self, ip, user=None, port = 22):
        self.ip = ip
        self.user = user
        self.port = port

    # High level function used to execute multiple commands over ssh
    # handles the establishing and breakdown of connection if not already connected
    def execute(self, lines, passwd = None):
        result_flag = True
        already_connected = self.isConnected
        if not already_connected:
            if not self.connect(passwd=passwd):
                logging.error('Could not connect to server')
                return False
        
        for line in lines:
            if not self.__executeLine(line = line):
                result_flag = False
                break
        
        if not already_connected:
            self.close()
        
        return result_flag
    
    # returns whether a connection can be established with given credentials
    def canConnect(self, user=None, passwd = None):
        if self.isConnected:
            self.close()
        if self.connect(user=user, passwd=passwd):
            self.close()
            self.isConnected = False
            return True
        return False

    # function which uses ftp to transfer remote file to local location
    def pullFile(self, remote_path, local_path, passwd = None):
        result_flag = True
        already_connected = self.isConnected
        if not already_connected:
            if not self.connect(passwd=passwd):
                logging.error('Could not connect to server')
                return False
            
        try: 
            ftp_client= self.client.open_sftp()
            ftp_client.get(remote_path, local_path)
            ftp_client.close() 
            result_flag = True
        except Exception as e:
            logging.error('Unable to download file from server\nerror: ', e)
            result_flag = False
            ftp_client.close()

        if not already_connected:
            self.close()

        return result_flag
    