#!/usr/bin/env python
'''
/*
 * This computer program is the confidential information and proprietary trade
 * secret of OpsRamp, Inc. Possessions and use of this program must  conform
 * strictly to the license agreement between the user and OpsRamp, Inc., and
 * receipt or possession does not convey any rights to divulge, reproduce,  or
 * allow others to use this program without specific written authorization  of
 * OpsRamp, Inc.
 *
 * Copyright (c) 2017 OpsRamp, Inc. All rights reserved.
 */
'''
import os, sys, platform
from optparse import OptionParser, OptionGroup

is_urllib_request = False
try:
    # For Python 3.0 and later
    from urllib.request import urlopen, install_opener, build_opener, Request, ProxyHandler
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode
    is_urllib_request = True
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib import urlencode
    from urllib2 import urlopen, install_opener, build_opener, Request, ProxyHandler, HTTPError, URLError


installType   = 'interactive'
InstalledBy   = 'opsramp'
api_server    = 'api.vistara.io'
api_port      = '443'
api_key       = 'Y3Wggg95SzNm87FWNcSwTUadNgeyGydn'
api_secret    = 'fBYpfUa3RBxxVXpNTjcDGm9Nkqrr3qmYSveEKAC8rdFV4HnvAbdAZGrj8HrmUQ9h'
client_id     = 'client_642869'

proxy_server  = 'PROXY_SERVER'
proxy_port    = 'PROXY_PORT'
proxy_user    = 'PROXY_USERNAME'
proxy_passwd  = 'PROXY_PASSWORD'
connection    = 'PROXY_TYPE'
proxy_prefix  = 'PROXY'
features      = 'agent:RemoteCommand,agent:PatchManagement,agent:Automation,agent:RemoteConsole'
device_uid   = ''

proxy_port = proxy_port.replace("PROXY_PORT", "3128")

usage = "Use the proper command line arguments. \nUsage: %prog  [-K key] [-S secret] [-s server] [-l <log-directory>] [-m 'proxy' -x <proxy-server> -p <proxy-port>]\n"
parser = OptionParser(usage=usage)
group = OptionGroup(parser, 'Optional parameters')
group.add_option("-K", "--key", dest="key", default="", help="Oauth API key authorization.")
group.add_option("-S", "--secret", dest="secret", default="", help="Oauth API secret.")
group.add_option("-c", "--clientid", dest="clientid", default="", help="Client unique ID.")
group.add_option("-v", "--agentversion", dest="agentversion", default="", help="Agent version that needs to be installed")
group.add_option("-u", "--InstalledBy", dest="InstalledBy", default="", help="Installed by user")
group.add_option("-s", "--server", dest="server", default="", help="Cloud server to connect. Example: api.opsramp.io")
group.add_option("-m", "--connection-mode", dest="connection", default="", help="The mode of connection - [direct] or proxy or gateway.")
group.add_option("-i", "--installtype", dest="installtype", default="", help="Install type - [interactive] or silent")
group.add_option("-x", "--proxy_server", dest="pserver", default="", help="Proxy server address to connect")
group.add_option("-p", "--proxy_port", dest="pport", default="", help="Proxy server port to connect")
group.add_option("-U", "--proxy_username", dest="pusername", default="", help="Proxy server authentication username to connect")
group.add_option("-P", "--proxy_password", dest="ppassword", default="", help="Proxy server authentication password to connect")
group.add_option("-l", "--log-dir", dest="logdir", default="", help="The path of the directory where agent logs are created. Default: /var/log/opsramp")
group.add_option("-f", "--features", dest="features", default="", help="features set to enable")
group.add_option("-H", "--uid", dest="deviceuid", default="", help="uid of device this can be host name")


parser.add_option_group(group)
(options, _args) = parser.parse_args()

if options.key != "":
    api_key = str(options.key.strip())

if options.secret != "":
    api_secret = str(options.secret.strip())

if options.clientid != "":
    client_id = str(options.clientid.strip())

if options.agentversion != "":
    agent_version = str(options.agentversion.strip())

if options.server != "":
    api_server = str(options.server.strip())

if options.InstalledBy != "":
    InstalledBy = str(options.InstalledBy.strip())

if options.logdir != "":
    log_dir = str(options.logdir.strip())

if options.pserver != "":
    proxy_server = str(options.pserver.strip())

if options.connection != "":
    connection = str(options.connection.strip())

if options.pport != "":
    proxy_port = str(options.pport.strip())

if options.pusername != "":
    proxy_user = str(options.pusername.strip())

if options.ppassword != "":
    proxy_passwd = str(options.ppassword.strip())

if options.installtype != "":
    installType = str(options.installtype.strip())

if options.features != "":
    features = str(options.features.strip())

if options.deviceuid != "":
    device_uid = str(options.deviceuid.strip())

if installType != 'silent':
    print ("""
Hello there! Happy to note that you have decided to install the OpsRamp Agent on this 
server. Linux OpsRamp Agent will greatly enhance your ability to remotely access this 
server, monitor and manage it.  Please note that the OpsRamp Agent install may require 
the download and install of other dependent packages. This will cause no side-effects. 
 
Enter 'y' to download packages and continue the install.
Enter 'n' to exit.""")

    c = sys.stdin.read(1)
    if c != 'y' and c != 'Y':
        sys.exit(1)

os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

class ReadException(Exception):
    pass


#################################
##     Read JSON object        ##
#################################
from re import compile, DOTALL
badOperators = '*'
slashstarcomment   = compile(r'/\*.*?\*/', DOTALL)
doubleslashcomment = compile(r'//.*\n')

regexes = {}
for operator in badOperators:
    if operator in '+*':
        # '+' and '*' need to be escaped with \ in re
        regexes[operator,'numeric operation'] = compile(r"\d*\s*\%s|\%s\s*\d*" % (operator, operator))
    else:
        regexes[operator,'numeric operation'] = compile(r"\d*\s*%s|%s\s*\d*" % (operator, operator))


def _Read(aString):
    """Use eval in a 'safe' way to turn javascript expression into
       a python expression.  Allow only True, False, and None in global
       __builtins__, and since those map as true, false, null in
       javascript, pass those as locals
    """
    try:
        result = eval(aString,
                      {"__builtins__":{'True': True, 'False': False, 'None': None}},
                      {'null': None, 'true': True, 'false': False})
    except NameError:
        raise ReadException("Strings must be quoted. Could not read '%s'." % (aString))
    except SyntaxError:
        raise ReadException("Syntax error. Could not read '%s'." % (aString))
    return result


def _getStringState(aSequence):
    """return the list of required quote closures if the end of aString needs them
    to close quotes.
    """
    state = []
    for k in aSequence:
        if k in ['"',"'"]:
            if state and k == state[-1]:
                state.pop()
            else:
                state.append(k)
    return state


def _sanityCheckMath(aString):
    """just need to check that, if there is a math operator in the
       client's JSON, it is inside a quoted string. This is mainly to
       keep client from successfully sending 'D0S'*9**9**9**9...
       Return True if OK, False otherwise
    """
    for operator in badOperators:
        #first check, is it a possible math operation?
        if regexes[(operator,'numeric operation')].search(aString) is not None:
            # OK.  possible math operation. get the operator's locations
            getlocs = regexes[(operator,'numeric operation')].finditer(aString)
            locs = [item.span() for item in getlocs]
            halfStrLen = len(aString) / 2
            #fortunately, this should be rare
            for loc in locs:
                exprStart = loc[0]
                exprEnd = loc[1]
                # We only need to know the char is within open quote
                # status.
                if exprStart <= halfStrLen:
                    teststr = aString[:exprStart]
                else:
                    teststr = list(aString[exprEnd+1:])
                    teststr.reverse()
                if not _getStringState(teststr):
                    return False
    return True


def safeRead(aString):
    """turn the js into happier python and check for bad operations
       before sending it to the interpreter
    """
    # get rid of trailing null. Konqueror appends this, and the python
    # interpreter balks when it is there.
    CHR0 = chr(0)
    while aString.endswith(CHR0):
        aString = aString[:-1]
    # strip leading and trailing whitespace
    aString = aString.strip()
    # zap /* ... */ comments
    aString = slashstarcomment.sub('',aString)
    # zap // comments
    aString = doubleslashcomment.sub('',aString)
    # here, we only check for the * operator as a DOS problem by default;
    # additional operators may be excluded by editing badOperators
    # at the top of the module
    if _sanityCheckMath(aString):
        return _Read(aString)
    else:
        raise ReadException('Unacceptable JSON expression: %s' % (aString))


def generate_minjson_adapter():
    class json(object):
        @staticmethod
        def loads(data):
            return safeRead(data)

    return json


try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = generate_minjson_adapter()



def executeCommand(cmd):
    try:
        if sys.version_info < (2, 7):
            import commands
            result = commands.getstatusoutput(cmd)
            return result[0] >> 8 , result[1]
        else:
            #args = shlex.split(cmd)
            import subprocess
            result = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            return 0, str(result).strip()
    except Exception:
        return -1, ""


def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)


def isCmdExists(program):
    try:
        fpath, fname = os.path.split(program)
        if fpath:
            return is_exe(program)
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return True
        return False
    except Exception:
        return False


def get_arch():
    try:
        arch = executeCommand("uname -m").strip()
        result = {"pentium": "i386",
                  "i86pc": "i386",
                  "x86_64": "amd64"}.get(arch)
        if result:
            arch = result
        elif (arch[0] == "i" and arch.endswith("86")):
            arch = "i386"
        return arch
    except Exception:
        return ''

def getOsDetails(os_string):
    os_array = os_string.split("\n")
    for value in os_array:
        output = value.split("=")
        if output[0] in ["NAME","VERSION","VERSION_ID"]:
            if output[0] == "NAME":
                os_name = output[1]
                os_distro = os_name.split(" ")[0]
                os_distro = os_distro.strip("'").lower()
            elif output[0] == "VERSION_ID":
                output[1]=output[1].replace('(','')
                output[1]=output[1].replace(')','')
                os_version = output[1].strip("'")
            elif output[0] == "VERSION":
                os_core = output[1].strip("'")

    return [ os_distro,os_name+" "+os_version+" "+os_core,os_version]

def getOSInfo():
    os_name = os_release = os_version = python_version = os_distro = ""
    try:
        curPF = sys.platform
        if curPF in ['linux', 'linux2']:
            if isCmdExists("lsb_release"):
                os_name = executeCommand("lsb_release -ds")[1].strip().strip("\"")
                os_version = executeCommand("lsb_release -rs")[1].strip()
                os_distro = executeCommand("lsb_release -is")[1].strip()
            else:
                if sys.version_info < (2, 6):
                    platformInfo = platform.dist()
                    os_name = platformInfo[0].strip("'").capitalize()
                    os_release = platformInfo[2].strip("'").capitalize()
                else:
                    platformInfo = platform.linux_distribution()
                    os_name = platformInfo[0].strip("'")
                    os_release = platformInfo[2].strip("'")
                if (os_name == ''):
                    platformInfo = executeCommand("cat /etc/*-release")
                    output = getOsDetails(platformInfo[1])
                    os_distro=output[0].strip('\"')
                    os_name=output[1].strip('\"')
                    os_version=output[2].strip('\"')
                    #print(os_distro)
                else:
                    os_version = platformInfo[1].strip("'")
                    os_name = os_name + " " + os_version + " " + os_release
                    os_distro = platform.dist()[0].strip("'").lower()

                osFile = ''
                if os.path.exists('/etc/oracle-release'):
                    osFile = '/etc/oracle-release'
                    os_distro = 'oracleserver'
                elif os.path.exists('/etc/redhat-release'):
                    osFile = '/etc/redhat-release'
                elif os.path.exists('/etc/fedora-release'):
                    osFile = '/etc/fedora-release'
                    os_distro = 'fedora'
                elif os.path.exists('/etc/system-release'):
                    osFile = '/etc/system-release'
                    os_distro = 'amazonami'
                elif os.path.exists('/etc/SuSE-release'):
                    osFile = '/etc/SuSE-release'
                    os_distro = 'sles'

                if osFile != '':
                    osFd = open(osFile, 'r')
                    os_name = osFd.readline().strip()
                    osFd.close()
                    if 'opensuse' in os_name.lower():
                        os_distro = 'suse'

                if os_distro == 'amazonami':
                    os_version = os_name.split()[-1]

        elif curPF == 'darwin':
            os_distro = 'darwin'
            if isCmdExists('sw_vers'):
                os_name = executeCommand("sw_vers -productName")[1].strip().strip("\"")
                os_version = executeCommand("sw_vers -productVersion")[1].strip().strip("\"")
            else:
                os_version = platform.mac_ver()[0]
                os_name = "Mac OS X"
            os_name = os_name + " " + os_version

        python_version = platform.python_version()
        return [os_name, os_version, os_distro, python_version]
    except:
        return [os_name, os_version, os_distro, python_version]



def checkPlatform():
    try:
        os_info = getOSInfo()
        os_distro = os_info[2]
        if isCmdExists("lsb_release"):
            if os_distro ==  "EnterpriseEnterpriseServer" and os.path.exists("/etc/oracle-release"):
                os_distro = "oracle"
            elif os_distro ==  "EnterpriseEnterpriseServer" and os.path.exists("/etc/redhat-release"):
                os_distro = "RedHatEnterpriseServer"
            elif 'opensuse' in os_info[0].lower():
                os_distro = "openSUSE project"

            os_distro = {
                "Ubuntu"           : "ubuntu",
                "Debian"           : "debian",
                "CentOS"           : "centos",
                "Fedora"           : "fedora",
                "AmazonAMI"        : "amazonami",
                "oracle"           : "oracleserver",
                "OracleServer"     : "oracleserver",
                "SUSE LINUX"       : "sles",
                "openSUSE project" : "suse",
                "RedHatEnterprise"       : "redhat",
                "RedHatEnterpriseServer" : "redhat",
                "CloudLinuxServer"       : "redhat",
                "OpenEnterpriseServer"   : "oes",
                "darwin"        : "darwin"

            }.get(os_distro, "unknown")
        return os_distro
    except:
        return "unknown"


def disable_cert_check_context():
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE
        return context
    except:
        return None


def allow_tls_only_context():
    try:
        import ssl
        encrption_protocol = ssl.PROTOCOL_TLSv1_2
        python_version = sys.version_info
        if (python_version[0] == 2 and python_version >= (2,7,13)) or (python_version[0] == 3 and python_version >= (3,6)):
            encrption_protocol = ssl.PROTOCOL_TLS

        context = ssl.SSLContext(encrption_protocol)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        return context
    except:
        return None


def downloadFile(download_url, dest, headers={}):
    try:
        block_sz = 8192

        ''' HTTP GET request for file download '''
        req = Request(download_url, None, headers)
        if proxy_server not in ['', proxy_prefix + '_SERVER']:
            if proxy_user != proxy_prefix + "_USERNAME":
                proxy_url = "http://%s:%s@%s:%s" % (proxy_user, proxy_passwd, proxy_server, proxy_port)
            else:
                proxy_url = "http://%s:%s" % (proxy_server, proxy_port)

            proxy_handler = ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = build_opener(proxy_handler)
            install_opener(opener)


        resp = None
        python_version = sys.version_info
        if (python_version[0] == 2 and python_version >= (2,7,9)) or (python_version[0] == 3 and python_version >= (3,4,3)):
            #resp = urlopen(req, context=allow_tls_only_context(), timeout=30)
            resp = urlopen(req, context=disable_cert_check_context(), timeout=30)
        elif python_version >= (2,6):
            resp = urlopen(req, timeout=30)
        else:
            resp = urlopen(req)

        ''' Write response content to file '''
        fd = open(dest, 'wb')
        while True:
            buffer = resp.read(block_sz)
            if not buffer:
                break
            fd.write(buffer)
        fd.close()

        resp.close()
        return True
    except HTTPError:
        print ("downloadFile: HTTP Error Exception")
        if os.path.exists("/usr/bin/curl"):
            print ("Downloading file - %s using curl" % (dest))
            if executeCommand("curl -k -H 'authorization: %s' %s -o %s" % (headers['authorization'], download_url, dest))[0] == 0:
                print ("File - %s has been successfully downloaded using curl" % (dest))
                return True
        return False
    except URLError:
        print ("downloadFile: URL Error Exception")
        return False


def httpRequest(url, headers={}, data=None):
    try:
        http_headers = {
            'Content-Type' : 'application/json',
            'Accept'       : '*/*'
        }
        http_headers.update(headers)
        req = Request(url, data, http_headers)
        if proxy_server not in ['', proxy_prefix + '_SERVER']:
            if proxy_user != proxy_prefix + '_USERNAME':
                proxy_url = "http://%s:%s@%s:%s" % (proxy_user, proxy_passwd, proxy_server, proxy_port)
            else:
                proxy_url = "http://%s:%s" % (proxy_server, proxy_port)
            proxy_handler = ProxyHandler({'http': proxy_url, 'https': proxy_url})
            install_opener(build_opener(proxy_handler))

        python_version = sys.version_info
        if (python_version[0] == 2 and python_version >= (2,7,9)) or (python_version[0] == 3 and python_version >= (3,4,3)):
            #return urlopen(req, context=allow_tls_only_context(), timeout=30).read()
            return urlopen(req, context=disable_cert_check_context(), timeout=30).read()
        elif python_version >= (2,6):
            return urlopen(req, timeout=30).read()
        else:
            return urlopen(req).read()
    except Exception:
        raise


def get_access_token():
    """ Block of code used to get Access Token from OpsRamp cloud by invoking OpsRamp Token API call """
    try:
        data = urlencode({
            "client_id"     : api_key,
            "client_secret" : api_secret,
            "grant_type"    : "client_credentials"
        })

        if is_urllib_request:
            data = data.encode()

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_url = "https://" + api_server + "/auth/oauth/token"

        resp = httpRequest(token_url, headers, data).decode()
        response = json.loads(resp)
        access_token = response["access_token"]
        token_type   = response["token_type"]
        return str(token_type) + " " + str(access_token)
    except Exception:
        raise

def get_agent_version(version_url, access_token):
    """ Block of code used to get agent version from OpsRamp cloud by invoking OpsRamp Token API call """
    try:
        headers = {
            "Accept"        : "application/json",
            "Content-Type"  : "application/json",
            "authorization" : access_token
        }
        return json.loads(httpRequest(version_url, headers).decode())
    except Exception:
        raise


def verify_and_install(distro, package):
    if distro in ["ubuntu", "debian"]:
        command = "dpkg -l %s |  grep -e '^ii' >/dev/null" % (package)
        if executeCommand(command)[0] != 0:
            print ("Initiating installation of missing dependency package '%s'" % (package))
            command = "apt-get -y install %s >/dev/null" % (package)
            resCode = executeCommand(command)[0]
            if resCode != 0:
                print ("Failed to install %s package. Hence exiting.." % (package))
                sys.exit(2)
            else:
                print ("Successfully installed agent dependency package '%s'" % (package))
    else:
        install_command = "yum install %s -y >/dev/null"
        if distro in ["sles", "suse"]:
            install_command = "zypper -n install %s >/dev/null"

        command = "rpm -qa | grep ^%s >/dev/null" % (package)
        if executeCommand(command)[0] != 0:
            print ("Initiating installation of missing dependency package '%s'" % (package))
            command = install_command % (package)
            resCode = executeCommand(command)[0]
            if resCode != 0:
                print ("Failed to install '%s' package. Hence exiting.." % (package))
                sys.exit(2)
            else:
                print ("Successfully installed agent dependency package '%s'" % (package))



distro = checkPlatform()
pythonVer = platform.python_version()
#device_arch = get_arch()
if distro == "darwin":
    device_arch = str(executeCommand("uname -m")[1])
else:
    device_arch = str(executeCommand("arch")[1])


''' Default command initializes to rpm based distros '''
pkgInstCmd    = "rpm -Uvh "
vistaraPkgChkCmd     = "rpm -qa | grep vistara-agent"
vistaraPkgUninstCmd  = "rpm -e vistara-agent; rm -rf /opt/vistara/agent; rmdir /opt/vistara > /dev/null 2>&1"
pkgChkCmd     = "rpm -qa | grep opsramp-agent-%s"
pkgUninstCmd  = "rpm -e opsramp-agent; rm -rf /opt/opsramp/agent; rmdir /opt/opsramp > /dev/null 2>&1"

osinfo = getOSInfo()
osVer  = osinfo[1]
print ("Detected %s %s (%s).." % (distro, osVer, device_arch))

device_distro = distro
# Check and install dependency packages
if distro in ["ubuntu", "debian"]:
    device_distro = "ubuntu"
    verify_and_install(distro, "python-apt")
    verify_and_install(distro, "dmidecode")

elif distro in ["centos", "redhat", "rhel", "fedora", "oracleserver", "amazonami"]:
    device_distro = "redhat"
    verify_and_install("redhat", "yum")
    verify_and_install("redhat", "dmidecode")
    if distro in ["centos", "redhat", "rhel", "oracleserver"] and osVer.startswith("5."):
        device_distro = "redhat5"

elif distro in ['sles']:
    device_distro = "sles"
    if osVer.startswith("11"):
        os_release = ".sles11"
        verify_and_install(distro, "python-dmidecode")

    elif osVer.startswith("12"):
        os_release = ".sles12"
        verify_and_install(distro, "dmidecode")
elif distro in ['suse']:
    device_distro = "sles"
    verify_and_install(distro, "dmidecode")
elif distro in ['darwin']:
    device_distro = "darwin"
else:
    print ("Unsupported OS distribution:")
    print ("OS Name    : " + osinfo[0])
    print ("OS Version : " + osinfo[1])
    print ("OS Distro  : " + osinfo[2])
    sys.exit(2)


# Frame the command for installation package
access_token = get_access_token()

if distro in ["ubuntu", "debian"]:
    pkgInstCmd = "dpkg -i --force-confnew "
    vistaraPkgChkCmd = "dpkg -l | grep vistara-agent"
    vistaraPkgUninstCmd = "dpkg -P vistara-agent; rm -rf /opt/vistara/agent; rmdir /opt/vistara > /dev/null 2>&1"
    pkgChkCmd = "dpkg -l | grep opsramp-agent | grep %s"
    pkgUninstCmd = "dpkg -P opsramp-agent; rm -rf /opt/opsramp/agent; rmdir /opt/opsramp > /dev/null 2>&1"
    if device_arch == 'x86_64':
        device_arch = 'amd64'
    elif device_arch == 'i386':
        device_arch = 'i686'
elif distro in ["darwin"]:
    pkgInstCmd = "installer -pkg %s -target /"
    vistaraPkgChkCmd = "pkgutil --pkgs | grep com.vistara.agent | grep version"
    pkgChkCmd = "pkgutil --pkgs | grep com.opsramp.agent | grep version"
    if device_arch == 'x86_64':
        device_arch = 'amd64'
    elif device_arch == 'i686':
        device_arch = 'i386'
elif distro in ["centos", "redhat", "rhel", "fedora", "suse", "sles", "oracleserver", "amazonami", "oes"]:
    if device_arch == 'amd64':
        device_arch = 'x86_64'
    elif device_arch == 'i686':
        device_arch = 'i386'


if device_distro == "darwin":
    version_url = "https://%s/api/v2/tenants/%s/agents/MAC/info?distName=%s&architecture=%s" % (api_server, client_id, device_distro, device_arch)
else:
    version_url = "https://%s/api/v2/tenants/%s/agents/LINUX/info?distName=%s&architecture=%s" % (api_server, client_id, device_distro, device_arch)

version_details = get_agent_version(version_url, access_token)
agent_version = str(version_details['version'])
pkg_name = str(version_details['name'])
pkg_size = int(version_details['size'])
pkg_path = "/tmp/" + pkg_name

pkg_download_status = False
if device_distro == "darwin":
    agent_dwld_url = "https://%s/api/v2/tenants/%s/agents/MAC/download/%s" % (api_server, client_id, pkg_name)
else:
    agent_dwld_url = "https://%s/api/v2/tenants/%s/agents/LINUX/download/%s" % (api_server, client_id, pkg_name)

if os.path.exists(pkg_path):
    if os.path.getsize(pkg_path) == pkg_size:
        pkg_download_status = True
    else:
        os.unlink(pkg_path)

if not pkg_download_status:
    if downloadFile(agent_dwld_url, pkg_path, {'authorization': access_token, 'Accept': 'application/octet-stream'}):
        if os.path.getsize(pkg_path) == pkg_size:
            pkg_download_status = True
            print ("Successfully downloaded the package " + pkg_name)
        else:
            print ("The agent package download is incomplete. Process terminating.")
            sys.exit(2)
    else:
        print ("Package couldn't be downloaded successfully. Process terminating.")
        sys.exit(2)

if device_distro != "darwin":
    pkgChkCmd = pkgChkCmd % (agent_version)

if executeCommand(vistaraPkgChkCmd)[0] == 0 and pkg_download_status:
    if device_distro == "darwin":
        if os.path.exists("/opt/vistara/agent/vistara-agent"):
            executeCommand("/opt/vistara/agent/vistara-agent uninstall")
        if os.path.exists("/opt/vistara/agent/bin/vistara-shield"):
            executeCommand("/opt/vistara/agent/bin/vistara-shield uninstall")
        if os.path.exists("/Library/LaunchDaemons/vistara-shield.plist"):
            executeCommand("rm -f /Library/LaunchDaemons/vistara-shield.plist")
        if os.path.exists("/Library/LaunchDaemons/vistara-agent.plist"):
            executeCommand("rm -f /Library/LaunchDaemons/vistara-agent.plist")
        if os.path.exists("/opt/vistara"):
            executeCommand("rm -rf /opt/vistara/")
        if os.path.exists("/var/log/vistara"):
            executeCommand("rm -rf /var/log/vistara/")
        if executeCommand("pkgutil --pkgs | grep com.vistara.agent")[0] == 0:
            executeCommand("pkgutil --forget com.vistara.agent >>dev/null")
    else:
        executeCommand(vistaraPkgUninstCmd)

if executeCommand(pkgChkCmd)[0] == 0 and pkg_download_status:
    if device_distro == "darwin":
        if os.path.exists("/opt/opsramp/agent/opsramp-agent"):
            executeCommand("/opt/opsramp/agent/opsramp-agent uninstall")
        if os.path.exists("/opt/opsramp/agent/bin/opsramp-shield"):
            executeCommand("/opt/opsramp/agent/bin/opsramp-shield uninstall")
        if os.path.exists("/Library/LaunchDaemons/opsramp-shield.plist"):
            executeCommand("rm -f /Library/LaunchDaemons/opsramp-shield.plist")
        if os.path.exists("/Library/LaunchDaemons/opsramp-agent.plist"):
            executeCommand("rm -f /Library/LaunchDaemons/opsramp-agent.plist")
        if os.path.exists("/opt/opsramp"):
            executeCommand("rm -rf /opt/opsramp/")
        if os.path.exists("/var/log/opsramp"):
            executeCommand("rm -rf /var/log/opsramp/")
        if executeCommand("pkgutil --pkgs | grep com.opsramp.agent")[0] == 0:
            executeCommand("pkgutil --forget com.opsramp.agent >>dev/null")
    else:
        executeCommand(pkgUninstCmd)


if not os.path.exists("/opt"):
    executeCommand("mkdir -p /opt")

if pkg_download_status:
    if device_distro == "darwin":
        pkgInstCmd = "installer -pkg %s -target /" % (pkg_path)
        instRes = executeCommand(pkgInstCmd)
    else:
        pkgInstCmd += pkg_path
        instRes = executeCommand(pkgInstCmd)

    if instRes[0] == 0:
        python_path = str(sys.executable)
        cmd = python_path + " /opt/opsramp/agent/bin/configure.py -K %s -S %s -s %s -v %s -f %s" % (api_key, api_secret, api_server, agent_version, features)
        if connection.lower() == "proxy":
            cmd = python_path + " /opt/opsramp/agent/bin/configure.py -K %s -S %s -s %s -v %s -f %s -m %s -x %s -p %s" % (api_key, api_secret, api_server, agent_version, features, connection, proxy_server, proxy_port)
        if device_uid != '' :
            cmd = cmd + " -H %s" % (device_uid)

        update_config = executeCommand(cmd)
        if update_config[0] == 0:
            print ("Started agent successfully.")
            executeCommand("rm -f " + pkg_path)
        else:
            print ("Failed to start the agent.")
            sys.exit(2)