'''
required
pip install paramiko
pip install cryptography==2.4.2
'''

import paramiko
import socket
import time
import re


class ShellHandler:

    def __init__(self, ssh):

        self.channel = ssh.invoke_shell()
        self.stdin = self.channel.makefile('wb')
        self.stdout = self.channel.makefile('r')
        time.sleep(0.5)
        self.channel.recv(9999)

    def execute_command_on_shell(self, command):
        """

        :param command: str
            command will get execute on shell
        :return: dic
            retutn dictonary with out, err, retval
        """

        command = command.strip('\n')
        self.stdin.write(f'{command} \n')
        finish = 'end of stdOUT buffer. finished with exit status'
        echo_cmd = f'echo {finish} $?'
        self.stdin.write(echo_cmd + '\n')
        self.stdin.flush()
        out = []
        err = []
        exit_status = 0

        for line in self.stdout:
            line = re.compile(r'\r\S').sub('', re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).replace('\b','')).replace('\r', '').replace('\n', '')
            if str(line).startswith(command) or str(line).startswith(echo_cmd):
                # up for now filled with shell junk from stdin
                out = []
            elif str(line).startswith(finish):
                # our finish command ends with the exit status
                exit_status = int(str(line).rsplit(maxsplit=1)[1])
                if exit_status:
                    err = out
                    out = []
                break
            else:
                # get rid of 'coloring and formatting' special characters
                out.append(re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).replace('\b', '').replace('\r', '').replace('\n', ''))
        # first and last lines of shout/sherr contain a prompt
        if out and echo_cmd[-3] in out[-1]:
            out.pop()
        if out and command in out[0]:
            out.pop(0)
        if err and echo_cmd in err[-1]:
            err.pop()
        if err and command in err[0]:
            err.pop(0)

        return {'out': out, 'err': err, 'retval': exit_status}


class SSH:

    instances = {}   # is dictionary which hold instance of paramiko.SSHClient() and ssh.invoke_shell()
    retry_count = 3  # retry count for execute_commands_in_shell function

    def __init__(self, hostname, username, password, ssh_instance_name=None):
        """ SSH object constructor

        Parameters
        ----------
        hostname : str
            The hostname of machine
        username : str
            The username created on machine
        password : str
            The password for username
        ssh_instance_name : str
            The name of ssh instance
        """

        self.hostname = hostname
        self.username = username
        self.password = password
        self.ssh_instance_name = ssh_instance_name
        self.__open_connection(self.hostname, self.username, self.password, self.ssh_instance_name)
        print(TAG + " | ssh to server successfully, Host: {}, User: {}".format(hostname, username))

    # def __del__(self):
    #     """ Destructor which will close the Open ssh connection
    #
    #     Raises
    #     ------
    #     retutn -1 on failed
    #     """
    #     try:
    #         print(TAG + " | ssh connection closed, Host: {}".format(self.hostname))
    #     except Exception as e:
    #         LOGGER.exception(TAG + " | Failed to close ssh on host: {} {}".format(self.hostname, e))

    def __open_connection(self, hostname, username, password, ssh_instance_name=None, port=22, key=None):
        """ Open the ssh connection on hostname with username and add it in instances dictionary

        Parameters
        ----------
        hostname : str
            The hostname of machine
        username : str
            The username created on machine
        password : str
            The password for username
        ssh_instance_name : str
            The name of ssh instance

        Raises
        ------
        retutn -1 on failed
        """

        if not SSH.instances or (hostname, username, password) not in SSH.instances.keys():

            try:

                proxy = None
                self.ssh = paramiko.SSHClient()
                #self.ssh.load_system_host_keys()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                #self.ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts"))
                if app_config.JUMPHOST_HOSTNAME and app_config.JUMPHOST_USERNAME and app_config.JUMPHOST_PASSWORD and app_config.JUMPHOST_PORT:
                    jumphost_channel = None
                    print(TAG + f'Using JUMPHOST : {app_config.JUMPHOST_HOSTNAME} for creating ssh instance')

                    jumphost = paramiko.SSHClient()
                    jumphost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    jumphost.connect(app_config.JUMPHOST_HOSTNAME, username=app_config.JUMPHOST_USERNAME, password=app_config.JUMPHOST_PASSWORD)

                    jumphost_transport = jumphost.get_transport()
                    jumphost_addr = (app_config.JUMPHOST_HOSTNAME, app_config.JUMPHOST_PORT)
                    adserver_addr = (hostname, port)
                    jumphost_channel = jumphost_transport.open_channel("direct-tcpip", adserver_addr, jumphost_addr)
                    print(TAG + f'| JUMPHOST : {app_config.JUMPHOST_HOSTNAME} channel is created')
                    print(TAG + f' | Creating ssh connection using jumphost_channel : {jumphost_channel}')
                    self.ssh.connect(hostname=hostname, username=username, password=password, port=port, key_filename=key, allow_agent=False, sock=jumphost_channel)
                else:
                    print(TAG + ' | Creating ssh connection without jumphost_channel')
                    self.ssh.connect(hostname=hostname, username=username, password=password, port=port, key_filename=key, allow_agent=False)
                self.shell = ShellHandler(self.ssh)
                print("connected to {} successfully".format(hostname))
                print(TAG + " | ssh connection opened, Host: {h}".format(h=self.hostname))
                SSH.instances[(hostname, username, password)] = {'ssh': self.ssh}
                print(TAG + f" | ssh connection added to singleton instances dictionary as a key 'ssh' under key {(hostname, username, password)}, ssh object: {self.ssh}")
                print(f'{TAG} | Shell invoked for {self.hostname}/{self.username}')
                self.retry_counter = 1
                SSH.instances[(hostname, username, password)]['shell'] = self.shell
                print(TAG + f" | shell is added to singleton instances dictionary as a key 'shell' under key {(hostname, username, password)}, ssh object: {self.shell}")
                if ssh_instance_name:
                    SSH.instances[ssh_instance_name] = {'ssh': self.ssh}
                    print(TAG + f" | ssh connection added to singleton instances dictionary as a key 'ssh' under key {ssh_instance_name}, ssh object: {self.ssh}")
                    SSH.instances[ssh_instance_name]['shell'] = self.shell
                    print(TAG + f" | shell is added to singleton instances dictionary as a key 'shell' under key {ssh_instance_name}, ssh object: {self.shell}")
            except paramiko.AuthenticationException:
                print("Authentication failed, please verify your credentials")
                result_flag = False
                raise
            except paramiko.SSHException as sshException:
                print("Could not establish SSH connection: {s}".format(s=sshException))
                result_flag = False
                raise
            except socket.timeout as e:
                print("Connection timed out")
                result_flag = False
                raise
            except Exception as e:
                LOGGER.exception(TAG + " | Failed to open ssh on host: {h} {e}".format(h=self.hostname, e=e))
                raise
        else:
            if ssh_instance_name:
                SSH.instances[ssh_instance_name] = SSH.instances[(hostname, username, password)]
            return self.get_instance(hostname, username, password, ssh_instance_name)

    def get_instance(self, hostname=None, username=None, password=None, ssh_instance_name=None):
        """

        :param hostname: str
            The hostname of machine
        :param username: str
            The username created on machine
        :param password: str
            The password for username
        :param ssh_instance_name: str
            The name of ssh instance
        :return:
            SSH object
            on failed return None
        """
        if (hostname, username, password) in SSH.instances.keys():
            self.ssh = SSH.instances[(hostname, username, password)]['ssh']
            print(TAG + f" | ssh connection returned from singleton instances dictionary of key 'ssh' under key {(hostname, username, password)}, ssh object: {SSH.instances[(hostname, username, password)]['ssh']}")
            self.shell = SSH.instances[(hostname, username, password)]['shell']
            print(TAG + f" | shell is returned from singleton instances dictionary of key 'shell' under key {(hostname, username, password)}, ssh object: {SSH.instances[(hostname, username, password)]['shell']}")
        else:
            if ssh_instance_name in SSH.instances.keys():
                self.ssh = SSH.instances[ssh_instance_name]['ssh']
                print(TAG + f" | ssh connection returned from singleton instances dictionary of key 'ssh' under key {ssh_instance_name}, ssh object: {SSH.instances[ssh_instance_name]['ssh']}")
                self.shell = SSH.instances[ssh_instance_name]['shell']
                print(TAG + f" | shell is returned from singleton instances dictionary of key 'shell' under key {ssh_instance_name}, ssh object: {SSH.instances[ssh_instance_name]['shell']}")
            else:
                LOGGER.error(TAG + f" | ssh connection not found in singleton instances dictionary of key {(hostname, username, password)}")
                LOGGER.error(TAG + f" | ssh connection not found in singleton instances dictionary of key {ssh_instance_name}")
                return None

    def is_connected(self, get_pty=False, timeout=20):
        """
        To check whether SSH connection is working or not
        :return:
            True  : if connection is established
            False : if connection is dropped
        """
        try:
            stdin, stdout, stderr = self.ssh.exec_command('hostname', get_pty=get_pty, timeout=timeout)
            stdin.write(app_config.ADS_PASSWORD + '\n')
            return True
        except Exception as e:
            LOGGER.exception(TAG + " | SSH connection is dropped with host: {h} {e}".format(h=self.hostname, e=e))
            return False

    def reconnect(self):
        """
        It just reconnect the ssh connection
        :return:
            True  : if get reconnect
            False : if failed to reconnect
        """
        try:
            if (self.hostname, self.username, self.password) in SSH.instances.keys():
                del SSH.instances[(self.hostname, self.username, self.password)]
                if self.ssh_instance_name in SSH.instances.keys():
                    del SSH.instances[self.ssh_instance_name]
                self.__open_connection(self.hostname, self.username, self.password, self.ssh_instance_name)
                print(TAG + f" | ssh reconnect to server successfully, Host: {self.hostname}, User: {self.username}")
            else:
                LOGGER.error(TAG + f" | given ssh connection is not in instances dictionary of key {(self.hostname, self.username, self.password)}")
        except:
            LOGGER.error(TAG + f" | ssh failed to reconnect for key {(self.hostname, self.username, self.password)}")

    def check_conection(func):
        def wrapper(self, *arg, **kwargs):
            if not self.is_connected():
                self.reconnect()
            return func(self, *arg, **kwargs)
        return wrapper

    def ping(self):
        """ Ping on hostname with objects open connection

        Raises
        ------
        retutn -1 on failed
        """
        try:
            stdin, stdout, stderr = self.ssh.exec_command("vmkping "+self.hostname)
            output = stdout.readlines()
            return output
        except Exception as e:
            LOGGER.exception(TAG + " | Failed to ping on host: {} {}".format(self.hostname, e))
            return None

    @check_conection
    def copy_from_local_to_server(self, localpath, remotepath):
        """ copy from location machine to server with username

        Parameters
        ----------
        localpath : str
            Absolute local path including filename
        remotepath : str
            Absolute remote path including filename, where needs to copy

        Raises
        ------
        retutn -1 on failed
        """
        try:
            if self.ssh.get_transport() is not None:
                self.ssh.get_transport().is_active()
            self.sftp = self.ssh.open_sftp()
            self.sftp.put(localpath, remotepath)
            print(TAG + " | Copy file success, local: {} => remote: {} ".format(localpath, remotepath))
            self.sftp.close()
            return True
        except Exception as e:
            LOGGER.exception(TAG + " | Failed copy file : {} => {}".format(localpath, remotepath))
            return False


    '''
    NOTE: Provide full path inclusing filename in local and remotepath
    '''

    @check_conection
    def copy_from_server_to_local(self, remotepath, localpath):
        """ copy from server machine to local with username

        Parameters
        ----------
        remotepath : str
            Absolute local path including filename
        localpath : str
            Absolute remote path including filename, where needs to copy

        Raises
        ------
        retutn -1 on failed
        """
        try:
            if self.ssh.get_transport() is not None:
                self.ssh.get_transport().is_active()
            self.sftp = self.ssh.open_sftp()
            self.sftp.get(remotepath, localpath)
            print(TAG + " | Copy file success, local: {} <= remote: {} ".format(remotepath, localpath))
            self.sftp.close()
            return True
        except Exception as e:
            LOGGER.exception(TAG + " | Failed copy file : {} <= {}".format(remotepath, localpath))
            return False

    @check_conection
    def is_process_running(self, process_name):
        """ check if process runing on machine

        Parameters
        ----------
        process_name : str
            process name case sensitive

        Raises
        ------
        retutn process id or -1 on failed
        """
        try:
            if process_name != None or process_name != "":
                pid = self.execute_command("pgrep {}".format(process_name))
                print(TAG + " | Process running, Process Name: {}, Process ID: {}".format(process_name, pid))
            return pid["out"][0]
        except Exception as e:
            print("Failed to check process {} ".format(process_name))
            LOGGER.exception(TAG + " | Failed to check process : {}".format(process_name))
            return None

    @check_conection
    def kill_process(self, process_name):
        """ check if process runing on machine

        Parameters
        ----------
        process_name : str
            process name case sensitive

        Raises
        ------
        retutn 0 on successfully killed, or -1 on failed
        """
        try:
            if process_name != None or process_name != "":
                self.execute_command("sudo kill -9 `pgrep {}`".format(process_name), True)
                print(TAG + " | Killing process , Process Name: {}".format(process_name))
                return True
        except Exception as e:
            LOGGER.exception(TAG + " | Failed to kill process : {}".format(process_name))
            return False

    @check_conection
    def execute_command(self, command, sudo=False, get_pty=False, timeout=20):
        """ execute_command on hostname wiht usrename or with sudo

        Parameters
        ----------
        command : str
            command need to execute on hostname with username
        sudo : boolean, option default false
            command will run with sudo if provided True else will execute with usermode

        Raises
        ------
        retutn dictonary with out, err, retval on success
        return -1 on execution failed
        """
        try:
            feed_password = False
            if sudo and self.username != "root":
                command = "sudo {command}".format(command=command)
            print(TAG + " | Executing command : {}".format(command))
            stdin, stdout, stderr = self.ssh.exec_command(command, get_pty=get_pty, timeout=timeout)
            stdin.write(self.password+'\n')
            exit_status = stdout.channel.recv_exit_status()
            out = [str(item).rstrip("\n") for item in stdout.readlines()]
            err = [str(item).rstrip("\n") for item in stderr.readlines()]
            if exit_status == 0:
                print("Command Executed successfully : {command}".format(command=command))
                print("Command o/p: {op}".format(op=out))
                print("Command error: {error}".format(error=err))
                print("Command execution status: {status}".format(status=exit_status))
            else:
                LOGGER.error("Error while executing command : {status}  !!".format(status=exit_status))
            return {'out': out,
                    'err': err,
                    'retval': exit_status}
        except Exception as e:
            LOGGER.exception(TAG + " | Failed to execute command : {}".format(command))
            return None

    def execute_commands_in_shell(self, commands):
        """ execute single or multiple command on shell

        :param commands: str  - for execute single command - execute_commands_in_shell('sudo su')
                         list - for execute multiple command - execute_commands_in_shell(['sudo su', 'whoami'])
        :return: return list of containing dictionary with out, err, retval for each command which is get executed only
        """
        ret_list = []
        retry = False

        try:
            if not isinstance(commands, list):
                commands = [commands]
            for cmd in commands:
                if str(self.shell.channel).split('(')[1].split(')')[0] == 'open':
                    if cmd == "sudo su":
                        cmd = "[ `whoami` != root ] && exec sudo su"  # Run sudo su only if non-root user.
                    print(TAG + f" | Executing command : {cmd}")
                    ret = self.shell.execute_command_on_shell(f'{cmd} \n')
                    ret_list.append({cmd: ret})
                    if ret['retval'] != 0:
                        break
                    else:
                        print(f"Command Executed successfully : {cmd}")
                    print(f"Command o/p: {ret['out']}")
                    print(f"Command error: {ret['err']}")
                    print(f"Command execution status: {ret['retval']}")
                else:
                    print(f'{TAG} | Shell get closed for {self.hostname}/{self.username}')
                    retry = True
                    break

            if retry:
                if not self.is_connected():
                    self.reconnect()
                if str(self.shell.channel).split('(')[1].split(')')[0] == 'closed':
                    self.shell = ShellHandler(self.ssh)
                    print(f'{TAG} | Shell invoked again for {self.hostname}/{self.username}')
                    SSH.instances[(self.hostname, self.username, self.password)]['shell'] = self.shell
                    print(TAG + f" | shell is added to singleton instances dictionary as a key 'shell' under key {(self.hostname, self.username, self.password)}, ssh object: {self.shell}")
                    if self.ssh_instance_name:
                        SSH.instances[self.ssh_instance_name]['shell'] = self.shell
                        print(TAG + f" | shell is added to singleton instances dictionary as a key 'shell' under key {self.ssh_instance_name}, ssh object: {self.shell}")
                if self.retry_counter <= SSH.retry_count:
                    print(f'{TAG} | Retry counter: {self.retry_counter} for execute_commands_in_shell')
                    self.retry_counter += 1
                    ret_list = self.execute_commands_in_shell(commands)
                    self.retry_counter -= 1
                else:
                    print('Max try reach out failed to run execute_commands_in_shell')
        except Exception as e:
            LOGGER.exception(f'{TAG} | execute_commands_in_shell failed due to {e}')
        return ret_list

    def close_connection(self):
        """ close the ssh connection from hostname

        Raises
        ------
        return -1 on execution failed
        """

        print(TAG + " | not allowed to close SSH connection | this function will remove after sometime !!")

        # try:
        #     self.ssh.close()
        #     print(TAG + " | clossing ssh connection")
        # except Exception as e:
        #     LOGGER.exception(TAG + "Failed to close ssh connection on host {}, {}".format(self.hostname, e))

    def __str__(self):
        return str(SSH.instances)

    def __repr__(self):
        return str(SSH.instances)

