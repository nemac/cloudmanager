cloudmanager
============

The `cloudmanager` script works together with `cirrus` to manage NEMAC's AWS cloud servers.

Requirements
------------

`cloudmanager` depends on the following:

* `cirrus` project must be set up and on your PATH
* `cloudconf` project must be available (for provisioning scripts, puppet manifests, etc)
* `CLOUDMANAGER_PROVISION_DIR` environment must should be set to the absolute path of
  the `cloudconf` project directory
* `cloudusers` project must be available (for user management)
* `CLOUDMANAGER_USERS` environment variable must be set to the absolute path of
  the `users.json` file in the `cloudusers` directory
  
Basic Usage
-----------

To view the current status of all AWS servers:

    cirrus ec2 ls

To update all currently running servers with the correct internal IP addresses of all
other servers:

    cloudmanager --hosts
    
To make a change to one or more user accounts, edit `users.json` accordingly, and then:

    cloudmanager --users
    
Then commit the new `users.json` file with an appropriate commit message, and push the
commit back to origin.

Provisioning
------------

Provisioning refers to the process of installing and configuring basic system software
on a server.  We use puppet for managing our server software configuration; each server's
configuration is controlled by a puppet file known as a "manifest".  Our puppet manifests
are stored in the `cloudconf` project, in a subdirectory called "puppet".  Puppet manifest
files end with a ".pp" suffix.  Each manifest corresponds to a particular type of server
configuration.  For example, the manifest "webserver-a.pp" is the one used for our basic
web servers (cloud0, cloud1).

Each of our AWS servers has a tag named "conf" which indicates which puppet manifest file
is used to control the configuration of that server; the value of the conf tag is the name
of the manifest file, without the ".pp" suffix.

You can see the list of these conf tags in the output of `cirrus ec2 ls`:

    ID          Name        Tags               Type        State    Public IP       Private IP      Key Name                                      Security Groups           
    i-8e9570f3  cloud0-a                       m2.2xlarge  stopped                                  /home/mbp/newcloud/keys/keypair1.pem          webserver                 
    i-af7917fc  cloud2                         m3.medium   stopped                                  /home/mbp/newcloud/keys/keypair1.pem          windows-arcgis-server-new 
    i-95627abf  cloud1      conf: webserver-a  m1.large    running  174.129.225.3   10.144.76.11    /home/mbp/newcloud/keys/keypair1.pem          webserver                 
    i-bd5a34ee  cloud3      conf: sshserver-a  t1.micro    running  54.235.183.101  10.212.106.122  /home/mbp/newcloud/keys/keypair1.pem          ssh-server                
    i-5c290f3d  cloud0      conf: webserver-a  m1.large    running  174.129.225.1   10.12.27.57     /home/mbp/newcloud/keys/keypair1.pem          webserver                 
    i-e95456c2  foo3        conf: webserver-a  t1.micro    running  54.242.36.198   10.208.233.115  /home/mbp/newcloud/keys/keypair1.pem          webserver                 
    i-28f8667b  cloud2.old                     m3.medium   stopped                                  /home/mbp/newcloud/keys/windows-arcgis-1.pem  windows arcgis server     
    i-1585823e  cloud4                         t1.micro    running  54.243.200.232  10.240.97.168   /home/mbp/newcloud/keys/keypair1.pem          webserver                 
    i-4a2c4b26  cloud1.old                     m1.large    stopped                                  /home/mbp/newcloud/keys/keypair1.pem          webserver                 

Servers that do not have a "conf" tag are ones where puppet is not being used, either
because they are running Windows, or because they are test servers not intended for 
production use.

To set the "conf" tag for a server:

    cloudmanager --conf webserver-a cloud4
    
Note that this does not actually modify anything on the server -- it just records the fact that
whenever the "cloud4" server is provisioned, it should be configured with the "webserver-a" puppet
manifest.

To provision a server:

    cloudmanager --provision cloud4

This will apply the latest version of the puppet manifest whose name is given by the server's
"conf" tag.
