import pwd, grp, os, re, subprocess, shutil, json, tempfile, sys

def system(cmd):
    #print cmd
    return os.system(cmd)

def bash_command(command):
    """Run command in a bash subshell, and return its output as a string"""
    return subprocess.Popen(['/bin/bash', '-c', command],
                            stdout=subprocess.PIPE).communicate()[0].strip()

def get_ssh_connection_field(field, ssh_config):
    m = re.search("^\\s*%s\\s+(\\S.*)$" % field, ssh_config, flags=re.MULTILINE)
    if m:
        return m.group(1)
    return None

def get_running_servers_info():
    """Return a dict representing the currently running servers; the keys of the dict
    are the names of the servers, and the value for each key is a dict containing vagrant
    ssh connection info for that server."""
    servers = json.loads(bash_command("cirrus -j ec2 ls"))
    #servers = bash_command("(cd .. ; find . -name .vagrant -print) | sed -e 's/\/\.vagrant//' -e 's/\.\///'").split("\n")
    server_dict = {}
    for server in servers:
        if server['State'] == 'running':
            tags = {}
            for kv in re.split(r'\s*[,\n]\s*', server['Tags']):
                if kv != "":
                    k, v = re.split(r'\s*:\s*', kv)
                    tags[k] = v
            server_dict[server['Name']] = {
                'IdentityFile': server['Key Name'],
                'PublicIP': server['Public IP'],
                'PrivateIP': server['Private IP'],
                'Tags' : tags,
                'User': 'root',
                'Port': '22'
            }
    return server_dict

def user_exists(username):
    try:
        pw = pwd.getpwnam(username)
        return True
    except KeyError:
        return False

def uid_exists(uid):
    try:
        pw = pwd.getpwuid(uid)
        return True
    except KeyError:
        return False

def group_exists(groupname):
    try:
        gp = grp.getgrnam(groupname)
        return True
    except KeyError:
        return False

def gid_exists(gid):
    try:
        gp = grp.getgrgid(gid)
        return True
    except KeyError:
        return False

def user_is_in_group(username, groupname):
    if not user_exists(username):
        raise Exception("User does not exist: %s" % username)
    try:
        g = grp.getgrnam(groupname)
    except KeyError:
        raise Exception("Group does not exist: %s" % groupname)
    try:
        members = g.gr_mem
    except:
        raise Exception("Error obtaining member list for group %s" % groupname)
    return username in members

def user_groups(username):
    """Return a list of the groups that USERNAME is a member of"""
    return re.sub('^%s\s*:\s*' % re.escape(username), '',
                  bash_command("/usr/bin/groups %s" % username)).split(" ")

def add_user_to_group(username, groupname):
    system("/usr/sbin/usermod -a -G %s %s" % (groupname,username))

def remove_user_from_group(username, groupname):
    if not user_exists(username):
        raise Exception("User does not exist: %s" % username)
    if not user_is_in_group(username, groupname):
        return
    groups = [g for g in user_groups(username) if (g != groupname)]
    system("/usr/sbin/usermod -G %s %s" % (",".join(groups),username))

def create_user(username, uid):
    if user_exists(username):
        raise Exception("User %s already exists" % username)
    if group_exists(username):
        raise Exception("Group %s already exists" % username)
    system("/usr/sbin/groupadd -g %s %s" % (uid, username))
    system("/usr/sbin/useradd -m -u %s -g %s %s" % (uid, username, username))
    system("/bin/mkdir /home/%s/.ssh" % username)
    system("/bin/chown %s.%s /home/%s/.ssh" % (username,username,username))
    system("/bin/chmod g=,o= /home/%s/.ssh" % username)

def create_user_gitconfig(username, realname, github_email):
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    gitconfig = "/home/%s/.gitconfig" % username
    if not os.path.exists(gitconfig):
        with open(gitconfig, "w") as f:
            f.write("[user]\n")
            f.write("        name = %s\n" % realname)
            f.write("        email = %s\n" % github_email)
    system("/bin/chown %s.%s %s" % (username,username,gitconfig))
    system("/bin/chmod u=rw,g=r,o=r %s" % gitconfig)

def update_user_ssh_keys(username, ssh_keys):
    authorized_keys = "/home/%s/.ssh/authorized_keys" % username
    #system("/bin/touch %s" % authorized_keys)
    with open(authorized_keys, "w") as f:
        for ssh_key in ssh_keys:
            f.write(ssh_key + "\n")
    system("/bin/chown %s.%s %s" % (username,username,authorized_keys))
    system("/bin/chmod g=r,o=r %s" % authorized_keys)

#
# 'git' priv grant/revoke:
#

def grant_user_git_priv(username, ssh_keys):
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    if not group_exists("git"):
        raise Exception("Group 'git' does not exist")
    if not user_is_in_group(username, 'git'):
        add_user_to_group(username, 'git')
    with open("/home/git/.ssh/authorized_keys", "r") as f:
        authorized_keys = f.read()
    for ssh_key in ssh_keys:
        comment = " user:%s\n" % username
        if not re.search("%s\\s+%s" % (re.escape(ssh_key), re.escape(comment)), authorized_keys):
            with open("/home/git/.ssh/authorized_keys", "a") as f:
                f.write("%s %s\n" % (ssh_key, comment))

def revoke_user_git_priv(username):
    if not group_exists("git"):
        return
    if user_exists(username) and user_is_in_group(username, 'git'):
        remove_user_from_group(username, 'git')
    with open("/home/git/.ssh/authorized_keys", "r") as f:
        lines = f.readlines()
    with open("/home/git/.ssh/authorized_keys", "w") as f:
        for line in lines:
            if not re.search("user:%s" % re.escape(username), line):
                f.write(line)

#
# 'mysql_root' priv grant/revoke:
#

def grant_user_mysql_root_priv(username):
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    system("/bin/cp /root/.my.cnf /home/%s" % username)
    system("/bin/chown %s.%s /home/%s/.my.cnf" % (username,username,username))

def revoke_user_mysql_root_priv(username):
    mycnf = "/home/%s/.my.cnf" % username
    if os.path.exists(mycnf):
        os.remove(mycnf)

#
# 'nappl' priv grant/revoke:
#

def grant_user_nappl_priv(username):
    if not group_exists("nappl"):
        raise Exception("Group 'nappl' does not exist")
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    if not user_is_in_group(username, 'nappl'):
        add_user_to_group(username, 'nappl')

def revoke_user_nappl_priv(username):
    if not group_exists("nappl"):
        return
    if user_exists(username) and user_is_in_group(username, 'nappl'):
        remove_user_from_group(username, 'nappl')

#
# 'mock' priv grant/revoke:
#

def grant_user_mock_priv(username):
    if not group_exists("mock"):
        raise Exception("Group 'mock' does not exist")
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    if not user_is_in_group(username, 'mock'):
        add_user_to_group(username, 'mock')

def revoke_user_mock_priv(username):
    if not group_exists("mock"):
        return
    if user_exists(username) and user_is_in_group(username, 'mock'):
        remove_user_from_group(username, 'mock')

#
# 'admin' priv grant/revoke:
#

def grant_user_admin_priv(username):
    if not group_exists("admin"):
        raise Exception("Group 'admin' does not exist")
    if not user_exists(username):
        raise Exception("User %s does not exist" % username)
    if not user_is_in_group(username, 'admin'):
        add_user_to_group(username, 'admin')

def revoke_user_admin_priv(username):
    if not group_exists("admin"):
        return
    if user_exists(username) and user_is_in_group(username, 'admin'):
        remove_user_from_group(username, 'admin')

#
# removing users
#
def remove_user(username):
    if user_exists(username):
        revoke_user_git_priv(username)
        system("/usr/sbin/userdel %s" % username)
    if group_exists(username):
        system("/usr/sbin/groupdel %s" % groupname)
    userhome = "/home/%s" % username
    if os.path.exists(userhome):
        shutil.rmtree(userhome)
    usermail = "/var/spool/mail/%s" % username
    if os.path.exists(usermail):
        os.remove(usermail)
    remove_from_etc_cloudusers(username)


def all_nappl_containers_and_usernames():
    """Return a list of dictionaries of info about each nappl application currently installed
    on this system.  Each dictionary has a key 'container' whose value is the name of the
    container, and optionally a 'username' key whose value is the user name associated
    with the container, if any."""
    appls = []
    for container_name in os.listdir("/var/nappl"):
        appl = { 'container' : container_name }
        path = "/var/nappl/" + container_name
        if os.path.isdir(path):
            metadata_file = path + "/metadata.json"
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    metadata = json.loads(f.read())
                if 'user' in metadata and 'name' in metadata['user']:
                    appl['username'] = metadata['user']['name']
                appls.append(appl)
    return appls



def remove_all_users_except(usernames, usertype, usertypes):
    """Remove all users with uid>=1000 except for accounts associated with
    nappl applications, and except for users of type `usertype` whose name
    appears in the list `usernames`, and except for users of any types
    listed in `usertypes` other than `usertype`.  For each user removed,
    also remove the group with the same name as the user, remove the home
    directory, and remove the user from /etc/cloudusers."""
    all_users = pwd.getpwall()
    nappl_usernames = [a['username'] for a in all_nappl_containers_and_usernames()]
    users_to_remove = [u for u in all_users if
                       ( u.pw_uid >= 1000
                         and
                         u.pw_name not in nappl_usernames )]
    # users_to_remove now consists of all non-system, non-nappl users
    # now remove from it all users of type usertype which are listed in usernames:
    utype = load_user_types()
    users_to_remove = [u for u in users_to_remove if not ( user_type(u.pw_name,utype) == usertype and u.pw_name in usernames )]
    # now remove from users_to_remove all users of all types in usertypes except usertype:
    other_types = [t for t in usertypes if t != usertype]
    users_to_remove = [u for u in users_to_remove if not user_type(u.pw_name,utype) in other_types]
    for u in users_to_remove:
        remove_user(u.pw_name)


etc_cloudusers = "/etc/cloudusers"
etc_cloudusers_tmp = "/etc/cloudusers.tmp"

def update_etc_cloudusers(username, usertype):
    if not os.path.exists(etc_cloudusers):
        os.system("touch " + etc_cloudusers)
    user_done = False
    with open(etc_cloudusers_tmp, "w") as f_out:
        with open(etc_cloudusers, "r") as f_in:
            for line in f_in.readlines():
                m = re.match(r'^([^:]+):([^:]+)$', line.strip())
                if m:
                    u = m.group(1)
                    t = m.group(2)
                    if (u == username):
                        f_out.write("%s:%s\n" % (username, usertype))
                        user_done = True
                    else:
                        f_out.write("%s:%s\n" % (u, t))
        if not user_done:
            f_out.write("%s:%s\n" % (username, usertype))
    os.rename(etc_cloudusers_tmp, etc_cloudusers)

def remove_from_etc_cloudusers(username):
    """Remove the given user from /etc/cloudusers."""
    if not os.path.exists(etc_cloudusers):
        # if /etc/cloudusers doesn't exist, there's nothing to do
        return
    found_user = False
    with open(etc_cloudusers_tmp, "w") as f_out:
        with open(etc_cloudusers, "r") as f_in:
            for line in f_in.readlines():
                m = re.match(r'^([^:]+):([^:]+)$', line.strip())
                if m:
                    u = m.group(1)
                    t = m.group(2)
                    if (u == username):
                        found_user = True
                    else:
                        f_out.write("%s:%s\n" % (u, t))
    # only touch /etc/cloudusers if user was deleted from it
    if found_user:
        os.rename(etc_cloudusers_tmp, etc_cloudusers)
    else:
        os.remove(etc_cloudusers_tmp)

def load_user_types():
    "Returns a dict whose keys are usernames, values are user types, read from /etc/cloudusers"
    types = {}
    with open(etc_cloudusers, "r") as f_in:
        for line in f_in.readlines():
            m = re.match(r'^([^:]+):([^:]+)$', line.strip())
            if m:
                u = m.group(1)
                t = m.group(2)
                types[u] = t
    return types

def user_type(username, utype):
    """Takes a string username, and dict whose keys are usernames and whose values are user types,
    and returns the type of the username.  If the username does not appear as a key of the dict,
    returns None."""
    if not username in utype:
        return None
    return utype[username]

#
# manageuser:
#

def manageuser(username, uid, privs, ssh_keys, realname, github_email, user_type, verbose=True):
    if not user_exists(username) and not uid_exists(uid):
        create_user(username, uid)
        if verbose:
            print "created user: %s [uid=%s]" % (username,uid)
    else:
        if verbose:
            print "user: %s [uid=%s]" % (username,uid)
    update_user_ssh_keys(username, ssh_keys)
    update_etc_cloudusers(username, user_type)
    if verbose:
        print "    updated ssh keys"

    if 'git' in privs:
        grant_user_git_priv(username, ssh_keys)
        if verbose:
            print "    granted git priv"
    else:
        revoke_user_git_priv(username)
        if verbose:
            print "    revoked git priv"

    if 'nappl' in privs:
        grant_user_nappl_priv(username)
        if verbose:
            print "    granted nappl priv"
    else:
        revoke_user_nappl_priv(username)
        if verbose:
            print "    revoked nappl priv"

    if 'admin' in privs:
        grant_user_admin_priv(username)
        if verbose:
            print "    granted admin priv"
    else:
        revoke_user_admin_priv(username)
        if verbose:
            print "    revoked admin priv"

    if 'mysql_root' in privs:
        grant_user_mysql_root_priv(username)
        if verbose:
            print "    granted mysql_root priv"
    else:
        revoke_user_mysql_root_priv(username)
        if verbose:
            print "    revoked mysql_root priv"

    if 'mock' in privs:
        grant_user_mock_priv(username)
        if verbose:
            print "    granted mock priv"
    else:
        revoke_user_mock_priv(username)
        if verbose:
            print "    revoked mock priv"

    if not os.path.exists("/home/%s/.gitconfig" % username):
        create_user_gitconfig(username, realname, github_email)
        if verbose:
            print "    created default .gitconfig"

def manage_etc_hosts_internal_ip_addresses(this_server, ip_addresses):
    etc_hosts = "/etc/hosts"
    etc_hosts_lines = []
    with open(etc_hosts, "r") as f:
        for line in [x.strip("\n")+"\n" for x in f.readlines()]: # make sure each line ends with a newline
            if not re.search(r'#\s*this line written by cloudmanager\s*$', line):
                etc_hosts_lines.append(line)
    for server in sorted(ip_addresses):
        if server == this_server:
            etc_hosts_lines.append("%-15s  %10s  %s.nemac.org   # this line written by cloudmanager\n" % (
                "127.0.0.1", "", this_server
            ))
        else:
            etc_hosts_lines.append("%-15s  %10s  %s.nemac.org   # this line written by cloudmanager\n" % (
                ip_addresses[server], server, server
            ))
    with open(etc_hosts, "w") as f:
        for line in etc_hosts_lines:
            f.write(line)

def script():
    # Returns a string
    # Note: __file__ is the abs path of this module file; sometimes that is 'cloudmanager.py', and
    # sometimes it is 'cloudmanager.pyc'.  The following makes sure that we always read the '.py'
    # version.
    cloudmanagerpy = os.path.join(os.path.dirname(__file__), "cloudmanager.py")
    s = "#! /usr/bin/python\n\n"
    with open(cloudmanagerpy, "r") as f:
        s += f.read()
    s += "\n###########################################\n"
    return s


def run_script_on_instance(instance_name, scriptpath=None, script=None, args="", noop=False):
    # Runs a script on an instance.  Should be called in one of the following ways:
    #     run_script_on_instance(instance_name, scriptpath=PATH, args)
    #         PATH is a string which is the absolute path of a local file containing a script
    #         to be run on the instance
    #     run_script_on_instance(instance_name, script=SCRIPT, args)
    #         SCRIPT is a string which is a script to be run on the instance (the actual code,
    #         as a string, not the path of a file containing code)
    # Only one of script,scriptpath may be given.  In both cases, `args` is optional.
    if scriptpath is None and script is not None:
        _, scriptpath = tempfile.mkstemp(prefix="cloudmanager-script-")
        with open(scriptpath, "w") as f:
            f.write(script)
    elif not (scriptpath is not None and script is None):
        raise Exception("run_script_on_instance must be called with exactly one of script,scriptpath")

    if noop:
        print "###"
        print "### script to run on server: %s" % instance_name
        print "###"
        with open(scriptpath) as f:
            print f.read()
        return

    scriptname = os.path.basename(scriptpath)
    system("cirrus ec2 rsync --options ' --no-owner --no-group' %(instance_name)s %(scriptpath)s /tmp" % {
        "instance_name"   : instance_name,
        "scriptpath"      : scriptpath
        })
    system("cirrus ec2 ssh %(instance_name)s 'chmod +x /tmp/%(scriptname)s'" % {
        "instance_name"   : instance_name,
        "scriptname"      : scriptname
        })
    system("cirrus ec2 ssh %(instance_name)s '/tmp/%(scriptname)s %(args)s'" % {
        "instance_name"   : instance_name,
        "scriptname"      : scriptname,
        "args"            : args
        })
    system("cirrus ec2 ssh %(instance_name)s '/bin/rm -f /tmp/%(scriptname)s'" % {
        "instance_name"   : instance_name,
        "scriptname"      : scriptname
        })
