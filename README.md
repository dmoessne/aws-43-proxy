# aws-43-proxy
OCP 4.3 setup on AWS via cli with proxy 

this is DRAFT and WIP - also see https://bugzilla.redhat.com/show_bug.cgi?id=1805125
- current flaws found
  - https proxy needs to be set although being similar to http proxy and no cert
  - additional endpoints need to be created and security groups added by terraform need to be added to EPs
   - com.amazonaws.<region>.elasticloadbalancing
   - com.amazonaws.<region>.ec2
  and attach them preferably during installation to the by terraform created security groups, as otherwise 
  workers cannot be created and masters are not correctly seen (possibly more side effects i did not notice)
  
  en detail so far - no guarantee - not final yet 
 
-----
  - have locally aws cli set up according to docs so we can use it right away:
~~~
$ sudo -i 
# curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
# unzip awscli-bundle.zip
# ./awscli-bundle/install -i /usr/local/aws -b /bin/aws
# /bin/aws --version
# logout

$ mkdir $HOME/.aws
$ export AWSKEY= <redacted>
$ export AWSSECRETKEY= <redacted>
$ export REGION=eu-west-1
$ cat << EOF >> $HOME/.aws/credentials
[default]
aws_access_key_id = ${AWSKEY}
aws_secret_access_key = ${AWSSECRETKEY}
region = $REGION
EOF

$ aws sts get-caller-identity
~~~
- now we can start creating aws objects from the local machine 

-------------------------------------------------------------------------------------------
- create vpc 
~~~
$ aws ec2 create-vpc --cidr-block 10.0.0.0/16
$ aws ec2 create-tags --resources vpc-04c5fa0e09be1cae7 --tags Key=Name,Value=dmoessne-vpc2
$ aws ec2 modify-vpc-attribute --vpc-id vpc-04c5fa0e09be1cae7 --enable-dns-hostnames
$ aws ec2 modify-vpc-attribute --vpc-id vpc-04c5fa0e09be1cae7 --enable-dns-support
$ aws ec2 describe-vpcs --vpc-ids vpc-04c5fa0e09be1cae7
$ aws ec2 describe-dhcp-options --dhcp-options-ids dopt-7d4aee18
~~~
-------------------------------------------------------------------------------------------
- create subnets 

~~~
$ aws ec2 create-subnet --vpc-id vpc-04c5fa0e09be1cae7 --availability-zone eu-west-1a --cidr-block 10.0.0.0/24
$ aws ec2 create-tags --resources subnet-0a57ce90ddc3ee179 --tags Key=Name,Value=dmoessne2-public-1a

$ aws ec2 create-subnet --vpc-id vpc-04c5fa0e09be1cae7 --availability-zone eu-west-1a --cidr-block 10.0.1.0/24
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-private-1a --resources subnet-05e26a80b438d3f0c

$ aws ec2 create-subnet --vpc-id vpc-04c5fa0e09be1cae7 --availability-zone eu-west-1b --cidr-block 10.0.2.0/24
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-private-1b --resources subnet-07e68f234ec25fdbc

$ aws ec2 create-subnet --vpc-id vpc-04c5fa0e09be1cae7 --availability-zone eu-west-1c --cidr-block 10.0.3.0/24
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-private-1c --resources subnet-008258ad985c916df
~~~

----------------------------------------------------------------------------------------------
- create internet gateway for bastion/proxy host in public network 

~~~
$ aws ec2 create-internet-gateway
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-igw --resources igw-0906e224dcfad7373
~~~

-------------------------------------------------------------------------------------------
- create routing tables:

~~~
$ aws ec2 create-route-table --vpc-id vpc-04c5fa0e09be1cae7
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-public-rtb --resources rtb-07e15e7aebbfb99b7

$ aws ec2 create-route-table --vpc-id vpc-04c5fa0e09be1cae7
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-private-rtb --resources rtb-09a14c33b16ed1d22
~~~

- link internetgateway to routing table to be associated with  public subnet 

~~~
$ aws ec2 create-route --route-table-id rtb-07e15e7aebbfb99b7 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-0906e224dcfad7373
~~~

- describe/check created routintables 
~~~
$ aws ec2 describe-route-tables --route-table-id rtb-07e15e7aebbfb99b7
$ aws ec2 describe-route-tables --route-table-id rtb-09a14c33b16ed1d22

$ aws ec2 describe-subnets --filters --filters "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7" --output text
~~~

- associate routing tables to subnets 

~~~
$ aws ec2 associate-route-table  --subnet-id subnet-0a57ce90ddc3ee179 --route-table-id rtb-07e15e7aebbfb99b7
$ aws ec2 associate-route-table  --route-table-id rtb-09a14c33b16ed1d22 --subnet-id subnet-008258ad985c916df
$ aws ec2 associate-route-table  --route-table-id rtb-09a14c33b16ed1d22 --subnet-id subnet-07e68f234ec25fdbc
$ aws ec2 associate-route-table  --route-table-id rtb-09a14c33b16ed1d22 --subnet-id subnet-subnet-05e26a80b438d3f0c
~~~

- replave default with custom  

~~~
$ aws ec2 describe-route-tables  --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7" --output text
$ aws ec2 replace-route-table-association --association-id rtbassoc-0eb6c034ce742b12a --route-table-id rtb-07e15e7aebbfb99b7
~~~

- remove default ruting table 
~~~
$ aws ec2 delete-route-table --route-table-id rtb-029e5a594c416d2e2
$ aws ec2 describe-route-tables  --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7" --output text
~~~

----------------------------------------------------------------------------------------------
- check Network ACLs 
  - already there:

~~~
$ aws ec2   describe-network-acls --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7"
~~~

--> we could make it even more restrictive for private nets, for now outbount is allowed all all
--> possibly revisit later 

----------------------------------------------------------------------------------------------
- create security groups (mostly needed for testing and the bastion/proxy)
- public-sg

~~~
$ aws ec2 create-security-group --description dmoessne-public-sg --group-name dmoessne-public-sg --vpc-id vpc-04c5fa0e09be1cae7
$ aws ec2 authorize-security-group-ingress --group-id  sg-0274aa6dbe8821264 --protocol tcp --port 22 --cidr 0.0.0.0/0
$ aws ec2 authorize-security-group-ingress --group-id  sg-0274aa6dbe8821264 --protocol all  --cidr 10.0.0.0/16
$ aws ec2 create-tags --resources sg-0274aa6dbe8821264 --tags Key=Name,Value=dmoessne2-sg-public
aws ec2   describe-security-groups --group-id sg-0274aa6dbe8821264
- private sg 
$ aws ec2 create-security-group --description dmoessne-private-sg --group-name dmoessne-private-sg --vpc-id vpc-04c5fa0e09be1cae7
$ aws ec2 create-tags --resources sg-0004d7665bdd62df6--tags Key=Name,Value=dmoessne2-sg-private
$ aws ec2 authorize-security-group-ingress --group-id sg-0004d7665bdd62df6  --protocol all  --cidr 10.0.0.0/16
$ aws ec2 authorize-security-group-egress --group-id  sg-0004d7665bdd62df6  --protocol all  --cidr 10.0.0.0/16
$ aws ec2 describe-security-groups --group-id sg-0004d7665bdd62df6
$ aws ec2 revoke-security-group-egress --group-id sg-0004d7665bdd62df6 --protocol all --cidr 0.0.0.0/0
$ aws ec2 describe-security-groups --group-id sg-0004d7665bdd62df6
~~~

----------------------------------------------------------------------------------------------
- create EPs

~~~
$ aws ec2 describe-vpc-endpoint-services

$ aws ec2 create-vpc-endpoint --vpc-endpoint-type Gateway --vpc-id vpc-04c5fa0e09be1cae7 --service-name com.amazonaws.eu-west-1.s3 --route-table-ids rtb-09a14c33b16ed1d22  --no-private-dns-enabled
$ aws ec2 create-tags --resources  vpce-05d7946b28bbd1c9a --tags Key=Name,Value=dmoessne2-EP-s3

$ aws ec2 describe-vpc-endpoints --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7"
$ aws ec2 create-vpc-endpoint --vpc-endpoint-type Interface --vpc-id vpc-04c5fa0e09be1cae7 --service-name com.amazonaws.eu-west-1.elasticloadbalancing --subnet-ids "subnet-008258ad985c916df" "subnet-07e68f234ec25fdbc" "subnet-05e26a80b438d3f0c" 
~~~

--private-dns-enabled

~~~
$ aws ec2 create-tags --resources vpce-0cea48f4aed2512be --tags Key=Name,Value=dmoessne2-EP-elb
$ aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0cea48f4aed2512be --remove-security-group-ids sg-0e157b13096816adc --add-security-group-ids sg-0004d7665bdd62df6

$ aws ec2 create-vpc-endpoint --vpc-endpoint-type Interface --vpc-id vpc-04c5fa0e09be1cae7 --service-name com.amazonaws.eu-west-1.ec2 --security-group-ids sg-0004d7665bdd62df6 --subnet-ids "subnet-008258ad985c916df" "subnet-07e68f234ec25fdbc" "subnet-05e26a80b438d3f0c" --private-dns-enabled
$ aws ec2 create-tags --resources vpce-0f7e1031539ad6509 --tags Key=Name,Value=dmoessne2-EP-ec2
~~~
----------------------------------------------------------------------------------------------

**Note:**
- security groups cretated by terraform are not added to the EPs, namely com.amazonaws.eu-west-1.elasticloadbalancing and com.amazonaws.eu-west-1.ec2 
- this leads to infuncional masters and workers are not being ctreated 
- to add master and node sgs to EPs:

~~~
$ aws ec2 describe-security-groups --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7" |egrep 'GroupId|master|worker' |egrep -B1 'master|worker'
$ aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0cea48f4aed2512be  --add-security-group-ids "" ""
$ aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0f7e1031539ad6509  --add-security-group-ids "" ""
~~~

- this can then be modified during or after the cluster has been created
- if done afterwards, the install will time out, export KUBECONFIG, check and verify co's are failing not getting ready, machinesets are nt created,...
- add the appropriate SGs to EPs and the cluster will fully come up 

----------------------------------------------------------------------------------------------
- create instances

- instance as bastion/proxy  (public network)

~~~
$ aws ec2 run-instances --image-id ami-04facb3ed127a2eb6 --count 1 --instance-type  t2.medium --key-name dmoessne-key --security-group-ids sg-0274aa6dbe8821264 --subnet-id subnet-0a57ce90ddc3ee179  --associate-public-ip-address
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-public-bastion --resources i-09c3f84bff7c9fe65
~~~

- instance in private nw to validate network has no internet access and proxy is working 

~~~
$ aws ec2 run-instances --image-id ami-0e61341fa75fcaa18 --count 1 --instance-type t2.micro --key-name dmoessne-key --security-group-ids sg-0004d7665bdd62df6 --subnet-id subnet-05e26a80b438d3f0c
$ aws ec2 create-tags --tags Key=Name,Value=dmoessne2-private-proxy-test --resources
~~~

- get IPs 

~~~
$ aws ec2 describe-instances --filters "Name=tag:Name,Values=dmoessne2*" --output text
~~~

----------------------------------------------------------------------------------------------
- login to VM in public network and set up aws cli, ocp related/needed tools to maintain and deploy ocp as well as a very simple proxy 

~~~
$ ssh -i ~/.ssh/dmoessne-key.pem ec2-user@ec2-<....>.eu-west-1.compute.amazonaws.com
~~~

----------------------------------------------------------------------------------------------
- become root and install needed packages (RHEL8)

~~~
$ sudo -i
# yum install -y firewalld squid vim wget unzip openssl python3 bind-utils
# alternatives --set python /usr/bin/python3
~~~
----------------------------------------------------------------------------------------------

- enable FW and enable squid ports 

~~~
# systemctl enable firewalld --now
# firewall-cmd --add-port=3128/tcp --permanent
# firewall-cmd --add-port=3128/tcp
~~~
----------------------------------------------------------------------------------------------

- set up squid (very simple) 

~~~
# cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
# vim /etc/squid/squid.conf
# cat /etc/squid/squid.conf
-------<snip>------------
acl SSL_ports port 443
# Ports where clients can connect to.
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
acl CONNECT method CONNECT

# if connection is not to any of this port, Sqiud rejects. otherwise check the next rule.
http_access deny !Safe_ports

# Squid cache manager app
http_access allow localhost manager
http_access deny manager

# localhost is allowed. if source is not localhost, squid checks the next rule
http_access allow localhost

# Simply allow everyone with everything - we are trusting everybody :D
http_access allow all

# IMPORTANT LINE: deny anything that's not allowed above
#http_access deny all

# listen on this port as a proxy
http_port 3128

# memory settings
cache_mem 512 MB
coredump_dir /var/spool/squid3

refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0 # refresh_pattern [-i] regex min percent max [options]
# here, . means 'any link'. Cache for at least 0, at most 20160 minutes, ot 50% of its age since 'last-modified' header.
refresh_pattern .		0	50%	20160

# delete x-forwarded-for header in requests (anonymize them)
forwarded_for delete
-----<snap>----------

# systemctl enable squid --now
~~~

----------------------------------------------------------------------------------------------
- aws cli/ocp tools install and config 

~~~
# curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
# unzip awscli-bundle.zip
# ./awscli-bundle/install -i /usr/local/aws -b /bin/aws
# /bin/aws --version

# wget -qO - https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-client-linux-4.3.1.tar.gz | tar xfz - -C /usr/bin/
# wget -qO - https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-install-linux-4.3.1.tar.gz | tar xfz - -C /usr/bin/

# oc completion bash >/etc/bash_completion.d/openshift
# oc version
# openshift-install version
# logout
~~~

----------------------------------------------------------------------------------------------
- configure aws tools as well on bastion 

~~~
$ mkdir $HOME/.aws
$ export AWSKEY= <redacted>
$ export AWSSECRETKEY= <redacted>
$ export REGION=eu-west-1
$ cat << EOF >> $HOME/.aws/credentials
[default]
aws_access_key_id = ${AWSKEY}
aws_secret_access_key = ${AWSSECRETKEY}
region = $REGION
EOF
$ 
$ aws sts get-caller-identity
~~~
  
----------------------------------------------------------------------------------------------
- create ssh key (basically follow docs) 

~~~
$ ssh-keygen -t rsa -b 2048 -N '' -f ~/.ssh/id_rsa
~~~

----------------------------------------------------------------------------------------------
- check ip for proxy  

~~~
$ ip a |grep 10.0.0
    inet 10.0.0.161/24 brd 10.0.0.255 scope global dynamic noprefixroute eth0 
~~~

----------------------------------------------------------------------------------------------
- configure install-config.yaml

~~~
$ vim install-config.yaml
$ cat install-config.yaml
-------<snip>-------
apiVersion: v1
baseDomain: dmoessne2.csa2-lab.org
proxy:
  httpProxy: http://10.0.0.161:3128
---
  httpsProxy: http://10.0.0.161:3128 <<-- looks like https needs to be set as well  --> confirmed when https is set although not different the upgrade part is working 
---
  noProxy: csa2-lab.org
controlPlane:
  hyperthreading: Enabled
  name: master
  platform:
    aws:
      zones:
      - eu-west-1a
      - eu-west-1b
      - eu-west-1c
      rootVolume:
        iops: 4000
        size: 500
        type: io1
      type: m5.xlarge
  replicas: 3
compute:
- hyperthreading: Enabled
  name: worker
  platform:
    aws:
      rootVolume:
        iops: 2000
        size: 500
        type: io1 
      type: m5.xlarge
      zones:
      - eu-west-1a
      - eu-west-1b
      - eu-west-1c
  replicas: 3
metadata:
  name: test-cluster
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineCIDR: 10.0.0.0/16
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  aws:
    region: eu-west-1
    userTags:
      adminContact: dmoessne
      costCenter: 118
    subnets: 
    - subnet-05e26a80b438d3f0c
    - subnet-07e68f234ec25fdbc
    - subnet-008258ad985c916df
pullSecret: '....'
fips: false
sshKey: 'ssh-rsa ...' 
publish: Internal
----<snap>------
~~~
----------------------------------------------------------------------------------------------


====== test proxy server from private subnet =====
- vm created earlier in priv subnet: 10.0.1.202
- proxy server: 10.0.0.161:3128


----------------------------------------------------------------------------------------------

- connect to VM in priv subnet 
[ec2-user@ip-10-0-0-161 ~]$ ssh -i ~/.ssh/dmoessne-key.pem 10.0.1.202
The authenticity of host '10.0.1.202 (10.0.1.202)' can't be established.
ECDSA key fingerprint is SHA256:rVN5VM5e3QrJm6eUcVhGSEuRyb8PL7vV2tuQhvU/X4E.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.1.202' (ECDSA) to the list of known hosts.

       __|  __|_  )
       _|  (     /   Amazon Linux AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2018.03-release-notes/
[ec2-user@ip-10-0-1-202 ~]$ 

----------------------------------------------------------------------------------------------

-- check DNS is working
[ec2-user@ip-10-0-1-202 ~]$ nslookup google.com 
Server:		10.0.0.2
Address:	10.0.0.2#53

Non-authoritative answer:
Name:	google.com
Address: 74.125.193.100
Name:	google.com
Address: 74.125.193.101
Name:	google.com
Address: 74.125.193.102
Name:	google.com
Address: 74.125.193.113
Name:	google.com
Address: 74.125.193.138
Name:	google.com
Address: 74.125.193.139

----------------------------------------------------------------------------------------------

- validate no connection is possible
[ec2-user@ip-10-0-1-202 ~]$ ping google.com
PING google.com (74.125.193.139) 56(84) bytes of data.
^C
--- google.com ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3068ms

[ec2-user@ip-10-0-1-202 ~]$ curl -vv google.com
* Rebuilt URL to: google.com/
*   Trying 74.125.193.138...
* TCP_NODELAY set
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
*   Trying 2a00:1450:400b:c01::8a...
* TCP_NODELAY set
* Immediate connect fail for 2a00:1450:400b:c01::8a: Network is unreachable
[ec2-user@ip-10-0-1-202 ~]$ 
----------------------------------------------------------------------------------------------


- set proxy and retest 

[ec2-user@ip-10-0-1-202 ~]$ 
[ec2-user@ip-10-0-1-202 ~]$ export http_proxy=http://10.0.0.161:3128
[ec2-user@ip-10-0-1-202 ~]$ export https_proxy=$http_proxy
[ec2-user@ip-10-0-1-202 ~]$ curl -vv google.com
* Rebuilt URL to: google.com/
* Uses proxy env variable http_proxy == 'http://10.0.0.161:3128'
*   Trying 10.0.0.161...
* TCP_NODELAY set
* Connected to 10.0.0.161 (10.0.0.161) port 3128 (#0)
> GET http://google.com/ HTTP/1.1
> Host: google.com
> User-Agent: curl/7.61.1
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
< HTTP/1.1 301 Moved Permanently
< Location: http://www.google.com/
< Content-Type: text/html; charset=UTF-8
< Date: Tue, 25 Feb 2020 18:03:19 GMT
< Expires: Thu, 26 Mar 2020 18:03:19 GMT
< Cache-Control: public, max-age=2592000
< Server: gws
< Content-Length: 219
< X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
< X-Cache: MISS from ip-10-0-0-161.eu-west-1.compute.internal
< X-Cache-Lookup: MISS from ip-10-0-0-161.eu-west-1.compute.internal:3128
< Via: 1.1 ip-10-0-0-161.eu-west-1.compute.internal (squid/4.4)
< Connection: keep-alive
< 
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
* Connection #0 to host 10.0.0.161 left intact
[ec2-user@ip-10-0-1-202 ~]$ curl -vv https://google.com
* Rebuilt URL to: https://google.com/
* Uses proxy env variable https_proxy == 'http://10.0.0.161:3128'
*   Trying 10.0.0.161...
* TCP_NODELAY set
* Connected to 10.0.0.161 (10.0.0.161) port 3128 (#0)
* allocate connect buffer!
* Establish HTTP proxy tunnel to google.com:443
> CONNECT google.com:443 HTTP/1.1
> Host: google.com:443
> User-Agent: curl/7.61.1
> Proxy-Connection: Keep-Alive
> 
< HTTP/1.1 200 Connection established
< 
* Proxy replied 200 to CONNECT request
* CONNECT phase completed!
* ALPN, offering h2
* ALPN, offering http/1.1
* Cipher selection: ALL:!EXPORT:!EXPORT40:!EXPORT56:!aNULL:!LOW:!RC4:@STRENGTH
* successfully set certificate verify locations:
*   CAfile: /etc/pki/tls/certs/ca-bundle.crt
  CApath: none
* TLSv1.2 (OUT), TLS header, Certificate Status (22):
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* CONNECT phase completed!
* CONNECT phase completed!
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-ECDSA-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=US; ST=California; L=Mountain View; O=Google LLC; CN=*.google.com
*  start date: Feb 12 11:47:11 2020 GMT
*  expire date: May  6 11:47:11 2020 GMT
*  subjectAltName: host "google.com" matched cert's "google.com"
*  issuer: C=US; O=Google Trust Services; CN=GTS CA 1O1
*  SSL certificate verify ok.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x1a4dd10)
> GET / HTTP/2
> Host: google.com
> User-Agent: curl/7.61.1
> Accept: */*
> 
* Connection state changed (MAX_CONCURRENT_STREAMS == 100)!
< HTTP/2 301 
< location: https://www.google.com/
< content-type: text/html; charset=UTF-8
< date: Tue, 25 Feb 2020 18:03:27 GMT
< expires: Thu, 26 Mar 2020 18:03:27 GMT
< cache-control: public, max-age=2592000
< server: gws
< content-length: 220
< x-xss-protection: 0
< x-frame-options: SAMEORIGIN
< alt-svc: quic=":443"; ma=2592000; v="46,43",h3-Q050=":443"; ma=2592000,h3-Q049=":443"; ma=2592000,h3-Q048=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000
< 
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
* Connection #0 to host 10.0.0.161 left intact
[ec2-user@ip-10-0-1-202 ~]$
----------------------------------------------------------------------------------------------
- logout agian 

[ec2-user@ip-10-0-1-202 ~]$ logout
Connection to 10.0.1.202 closed.
[ec2-user@ip-10-0-0-161 ~]$ 

----------------------------------------------------------------------------------------------

- finally, let's deploy and see where we end up 
mkdir ~/cluster
cp install-config.yaml ~/cluster
openshift-install create cluster --dir=./cluster --log-level debug

at stage  DEBUG Terraform has been successfully initialized and when gs are created we need to add them to the right endpoints, othersie the install does not complete as no nodes are created,........
this can be done later and cluster recovers 
-------
meanwhile - can be done later too, but leads to an error ..
[dmoessne@frodo ~]$ aws ec2 describe-security-groups --filter "Name=vpc-id,Values=vpc-04c5fa0e09be1cae7" |egrep 'GroupId|master|worker' |egrep -B1 'master|worker'
            "GroupId": "sg-09462f9dcbe9f1415",
                    "Value": "test-cluster-72qvd-master-sg"
--
            "GroupId": "sg-095237c3631e85c7b",
                    "Value": "test-cluster-72qvd-worker-sg"
[dmoessne@frodo ~]$ 

[dmoessne@frodo ~]$ aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0f7e1031539ad6509  --add-security-group-ids sg-09462f9dcbe9f1415 sg-095237c3631e85c7b
{
    "Return": true
}
[dmoessne@frodo ~]$ aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0cea48f4aed2512be  --add-security-group-ids sg-095237c3631e85c7b sg-095237c3631e85c7b
{
    "Return": true
}
------------------

[ec2-user@ip-10-0-0-161 ~]$ openshift-install create cluster --dir=./cluster --log-level debug
DEBUG OpenShift Installer v4.3.1                   
DEBUG Built from commit 2055609f95b19322ee6cfdd0bea73399297c4a3e 
DEBUG Fetching Terraform Variables...              
DEBUG Loading Terraform Variables...               
DEBUG   Loading Cluster ID...                      
DEBUG     Loading Install Config...                
DEBUG       Loading SSH Key...                     
DEBUG       Loading Base Domain...                 
DEBUG         Loading Platform...                  
DEBUG       Loading Cluster Name...                
DEBUG         Loading Base Domain...               
DEBUG         Loading Platform...                  
DEBUG       Loading Pull Secret...                 
DEBUG       Loading Platform...                    
DEBUG     Using Install Config loaded from target directory 
...
DEBUG Still waiting for the Kubernetes API: Get https://api.test-cluster.dmoessne2.csa2-lab.org:6443/version?timeout=32s: dial tcp 10.0.1.241:6443: connect: connection refused 
INFO API v1.16.2 up                               
INFO Waiting up to 30m0s for bootstrapping to complete... 
DEBUG Bootstrap status: complete                   
INFO Destroying the bootstrap resources...        
DEBUG Symlinking plugin terraform-provider-aws src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-aws" 
DEBUG Symlinking plugin terraform-provider-azurerm src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-azurerm" 
DEBUG Symlinking plugin terraform-provider-azureprivatedns src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-azureprivatedns" 
DEBUG Symlinking plugin terraform-provider-google src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-google" 
DEBUG Symlinking plugin terraform-provider-ignition src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-ignition" 
DEBUG Symlinking plugin terraform-provider-local src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-local" 
DEBUG Symlinking plugin terraform-provider-openstack src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-openstack" 
DEBUG Symlinking plugin terraform-provider-random src: "/usr/bin/openshift-install" dst: "/tmp/openshift-install-728759855/plugins/terraform-provider-random" 
DEBUG Initializing modules...                      
DEBUG - bootstrap in ../../tmp/openshift-install-728759855/bootstrap 
DEBUG - dns in ../../tmp/openshift-install-728759855/route53 
DEBUG - iam in ../../tmp/openshift-install-728759855/iam 
DEBUG - masters in ../../tmp/openshift-install-728759855/master 
DEBUG - vpc in ../../tmp/openshift-install-728759855/vpc 
DEBUG                                              
DEBUG Initializing the backend...                  
DEBUG                                              
DEBUG Initializing provider plugins...             
DEBUG                                              
DEBUG Terraform has been successfully initialized! 
DEBUG                                              
DEBUG You may now begin working with Terraform. Try running "terraform plan" to see 
DEBUG any changes that are required for your infrastructure. All Terraform commands 
DEBUG should now work.                             
DEBUG                                              
....
DEBUG Destroy complete! Resources: 11 destroyed.   
INFO Waiting up to 30m0s for the cluster at https://api.test-cluster.dmoessne2.csa2-lab.org:6443 to initialize... 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 97% complete 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete, waiting on authentication, console, image-registry, monitoring 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete, waiting on authentication, console, image-registry, monitoring 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete, waiting on authentication, console, monitoring 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete, waiting on authentication, console, monitoring 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete, waiting on authentication, console, monitoring 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 99% complete 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 100% complete, waiting on authentication 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 100% complete, waiting on authentication 
DEBUG Still waiting for the cluster to initialize: Working towards 4.3.1: 100% complete, waiting on authentication 
DEBUG Still waiting for the cluster to initialize: Cluster operator authentication is still updating 
DEBUG Still waiting for the cluster to initialize: Cluster operator authentication is still updating 
DEBUG Cluster is initialized                       
INFO Waiting up to 10m0s for the openshift-console route to be created... 
DEBUG Route found in openshift-console namespace: console 
DEBUG Route found in openshift-console namespace: downloads 
DEBUG OpenShift console route is created           
INFO Install complete!                            
INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/home/ec2-user/cluster/auth/kubeconfig' 
INFO Access the OpenShift web-console here: https://console-openshift-console.apps.test-cluster.dmoessne2.csa2-lab.org 
INFO Login to the console with user: kubeadmin, password: hEMYP-JDuAg-KRveS-WPdnL 
[ec2-user@ip-10-0-0-161 ~]$ 

----------------------------------------------------------------------------------------------
- 2 ways possible here 
  1. you added the by terraform created SGs as done here to the EPs --> installer will succeed and we can go on as shown above
  2. you did not, so you will find the installer running into timout complaining several components are not ready 
    -> you can still run export KUBECONFIG=/home/ec2-user/cluster/auth/kubeconfig
    -> and verify that co as failing, 
              -  oc get machines -n openshift-machine-api 
              -  oc get machinesets -n openshift-machine-api 
       are showing no (for master) or incomplete (worker) output
    -> no workers are created, hence certain needed pods could not deployed and install seems to fail
   ==> add as above the by terraform created SGs to the Endpoints and wait some time, you will see
       - machinesets,machines and worker nodes ctreated and eventually cluster gets successfully deployed 
----------------------------------------------------------------------------------------------

- export KUBECONFIG and check status

$ export KUBECONFIG=/home/ec2-user/cluster/auth/kubeconfig

$ oc get co 
NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE
authentication                             4.3.1     True        False         False      19m
cloud-credential                           4.3.1     True        False         False      43m
cluster-autoscaler                         4.3.1     True        False         False      34m
console                                    4.3.1     True        False         False      28m
dns                                        4.3.1     True        False         False      38m
image-registry                             4.3.1     True        False         False      32m
ingress                                    4.3.1     True        False         False      33m
insights                                   4.3.1     True        False         False      40m
kube-apiserver                             4.3.1     True        False         False      39m
kube-controller-manager                    4.3.1     True        False         False      37m
kube-scheduler                             4.3.1     True        False         False      36m
machine-api                                4.3.1     True        False         False      39m
machine-config                             4.3.1     True        False         False      38m
marketplace                                4.3.1     True        False         False      34m
monitoring                                 4.3.1     True        False         False      25m
network                                    4.3.1     True        False         False      38m
node-tuning                                4.3.1     True        False         False      34m
openshift-apiserver                        4.3.1     True        False         False      37m
openshift-controller-manager               4.3.1     True        False         False      39m
openshift-samples                          4.3.1     True        False         False      33m
operator-lifecycle-manager                 4.3.1     True        False         False      39m
operator-lifecycle-manager-catalog         4.3.1     True        False         False      39m
operator-lifecycle-manager-packageserver   4.3.1     True        False         False      35m
service-ca                                 4.3.1     True        False         False      40m
service-catalog-apiserver                  4.3.1     True        False         False      35m
service-catalog-controller-manager         4.3.1     True        False         False      35m
storage                                    4.3.1     True        False         False      35m
$ 

$ oc adm upgrade
Cluster version is 4.3.1

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
$ 
----------------------------------------------------------------------------------------------

- for testing purposes we change the channel to candidate DO NOT USE THIS IN PROD AND EVEN BE CAREFUL FOR TESTS : https://access.redhat.com/articles/4495171

$ oc get clusterversions.config.openshift.io  -o yaml 
apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterVersion
  metadata:
    creationTimestamp: "2020-02-25T21:56:40Z"
    generation: 1
    name: version
    resourceVersion: "17488"
    selfLink: /apis/config.openshift.io/v1/clusterversions/version
    uid: 8aa2a79f-0948-4cda-b7d8-e38d54a54a54
  spec:
    channel: stable-4.3
[....]
$ oc edit clusterversion 
clusterversion.config.openshift.io/version edited
$ 
$ oc get clusterversions.config.openshift.io  -o yaml 
apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterVersion
  metadata:
    creationTimestamp: "2020-02-25T21:56:40Z"
    generation: 2
    name: version
    resourceVersion: "19272"
    selfLink: /apis/config.openshift.io/v1/clusterversions/version
    uid: 8aa2a79f-0948-4cda-b7d8-e38d54a54a54
  spec:
    channel: candidate-4.3
[....]
$
$ oc logs -f cluster-version-operator-558c886d49-7x5nn -n openshift-cluster-version
....
I0225 22:23:48.638083       1 cvo.go:479] Started syncing upgradeable "openshift-cluster-version/version" (2020-02-25 22:23:48.638075824 +0000 UTC m=+1513.485831826)
I0225 22:23:48.638229       1 upgradeable.go:28] Upgradeable conditions were recently checked, will try later.
I0225 22:23:48.638266       1 cvo.go:481] Finished syncing upgradeable "openshift-cluster-version/version" (187.625µs)
I0225 22:23:48.638133       1 cvo.go:392] Started syncing cluster version "openshift-cluster-version/version" (2020-02-25 22:23:48.638128463 +0000 UTC m=+1513.485884443)
I0225 22:23:48.638330       1 cvo.go:424] Desired version from operator is v1.Update{Version:"4.3.1", Image:"quay.io/openshift-release-dev/ocp-release@sha256:ea7ac3ad42169b39fce07e5e53403a028644810bee9a212e7456074894df40f3", Force:false}
I0225 22:23:48.638467       1 cvo.go:394] Finished syncing cluster version "openshift-cluster-version/version" (335.206µs)
I0225 22:23:48.638148       1 cvo.go:456] Started syncing available updates "openshift-cluster-version/version" (2020-02-25 22:23:48.638144638 +0000 UTC m=+1513.485900587)
I0225 22:23:48.960473       1 cvo.go:458] Finished syncing available updates "openshift-cluster-version/version" (322.321043ms)
I0225 22:23:48.960501       1 cvo.go:392] Started syncing cluster version "openshift-cluster-version/version" (2020-02-25 22:23:48.960497374 +0000 UTC m=+1513.808253381)
I0225 22:23:48.960548       1 cvo.go:424] Desired version from operator is v1.Update{Version:"4.3.1", Image:"quay.io/openshift-release-dev/ocp-release@sha256:ea7ac3ad42169b39fce07e5e53403a028644810bee9a212e7456074894df40f3", Force:false}
I0225 22:23:48.960617       1 cvo.go:394] Finished syncing cluster version "openshift-cluster-version/version" (118.025µs)
I0225 22:23:53.226569       1 cvo.go:392] Started syncing cluster version "openshift-cluster-version/version" (2020-02-25 22:23:53.226559976 +0000 UTC m=+1518.074315988)
I0225 22:23:53.226624       1 cvo.go:424] Desired version from operator is v1.Update{Version:"4.3.1", Image:"quay.io/openshift-release-dev/ocp-release@sha256:ea7ac3ad42169b39fce07e5e53403a028644810bee9a212e7456074894df40f3", Force:false}
I0225 22:23:53.226692       1 cvo.go:394] Finished syncing cluster version "openshift-cluster-version/version" (129.724µs)
^C
$
$ oc adm upgrade
Cluster version is 4.3.1

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
$ 
$ oc adm upgrade --to-latest
Updating to latest version 4.3.2
$ date; oc adm upgrade
Tue Feb 25 22:26:06 UTC 2020
Cluster version is 4.3.1

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550

$ date; oc adm upgrade
Tue Feb 25 22:26:46 UTC 2020
info: An upgrade is in progress. Unable to apply 4.3.2: the update could not be applied

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
$ oc adm upgrade
info: An upgrade is in progress. Unable to apply 4.3.2: the update could not be applied

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
$ oc adm upgrade
info: An upgrade is in progress. Unable to apply 4.3.2: the update could not be applied

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
$ oc adm upgrade
info: An upgrade is in progress. Working towards 4.3.2: 10% complete

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
$ date; oc adm upgrade
Tue Feb 25 22:29:06 UTC 2020
info: An upgrade is in progress. Working towards 4.3.2: 16% complete

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
$ 


$ oc get co 
NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE
authentication                             4.3.2     True        False         False      46m
cloud-credential                           4.3.2     True        False         False      63m
cluster-autoscaler                         4.3.2     True        False         False      55m
console                                    4.3.2     True        False         False      4m50s
dns                                        4.3.2     True        False         False      59m
image-registry                             4.3.2     True        False         False      5m22s
ingress                                    4.3.2     True        False         False      5m18s
insights                                   4.3.2     True        False         False      61m
kube-apiserver                             4.3.2     True        False         False      58m
kube-controller-manager                    4.3.2     True        False         False      57m
kube-scheduler                             4.3.2     True        False         False      57m
machine-api                                4.3.2     True        False         False      60m
machine-config                             4.3.1     True        True          False      59m
marketplace                                4.3.2     True        False         False      10s
monitoring                                 4.3.2     True        False         False      20m
network                                    4.3.2     True        False         False      59m
node-tuning                                4.3.2     True        False         False      72s
openshift-apiserver                        4.3.2     True        False         False      19m
openshift-controller-manager               4.3.2     True        False         False      58m
openshift-samples                          4.3.2     True        False         False      25m
operator-lifecycle-manager                 4.3.2     True        False         False      60m
operator-lifecycle-manager-catalog         4.3.2     True        False         False      60m
operator-lifecycle-manager-packageserver   4.3.2     True        False         False      19s
service-ca                                 4.3.2     True        False         False      61m
service-catalog-apiserver                  4.3.2     True        False         False      57m
service-catalog-controller-manager         4.3.2     True        False         False      57m
storage                                    4.3.2     True        False         False      25m
$ 
$ oc project openshift-machine-api 

$ oc get mc |grep 10m$
rendered-master-5861a738deb2dc2af9a0b78ca14bdc0f            3ad3a836ba89556b422454b4e5614dbd031ea3a3   2.2.0             10m
rendered-worker-ad5345eeacf011c37d9aa14aaf366303            3ad3a836ba89556b422454b4e5614dbd031ea3a3   2.2.0             10m
$ 
$ oc get mcp
NAME     CONFIG                                             UPDATED   UPDATING   DEGRADED   MACHINECOUNT   READYMACHINECOUNT   UPDATEDMACHINECOUNT   DEGRADEDMACHINECOUNT
master   rendered-master-945d021c2ea5c0704633b5ca04cdcb38   False     True       False      3              2                   2                     0
worker   rendered-worker-ad5345eeacf011c37d9aa14aaf366303   True      False      False      3              3                   3                     0
$ 
$ oc get nodes 
NAME                                       STATUS                     ROLES    AGE   VERSION
ip-10-0-1-18.eu-west-1.compute.internal    Ready                      worker   55m   v1.16.2
ip-10-0-1-21.eu-west-1.compute.internal    Ready                      master   63m   v1.16.2
ip-10-0-2-128.eu-west-1.compute.internal   Ready,SchedulingDisabled   master   63m   v1.16.2
ip-10-0-2-217.eu-west-1.compute.internal   Ready                      worker   55m   v1.16.2
ip-10-0-3-176.eu-west-1.compute.internal   Ready                      master   63m   v1.16.2
ip-10-0-3-34.eu-west-1.compute.internal    Ready                      worker   55m   v1.16.2
$ oc get nodes  -o wide
NAME                                       STATUS                     ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE                                                       KERNEL-VERSION                CONTAINER-RUNTIME
ip-10-0-1-18.eu-west-1.compute.internal    Ready                      worker   55m   v1.16.2   10.0.1.18     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-1-21.eu-west-1.compute.internal    Ready                      master   63m   v1.16.2   10.0.1.21     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-2-128.eu-west-1.compute.internal   Ready,SchedulingDisabled   master   63m   v1.16.2   10.0.2.128    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002032142.0 (Ootpa)   4.18.0-147.3.1.el8_1.x86_64   cri-o://1.16.2-15.dev.rhaos4.3.gita83f883.el8
ip-10-0-2-217.eu-west-1.compute.internal   Ready                      worker   55m   v1.16.2   10.0.2.217    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-3-176.eu-west-1.compute.internal   Ready                      master   63m   v1.16.2   10.0.3.176    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-3-34.eu-west-1.compute.internal    Ready                      worker   55m   v1.16.2   10.0.3.34     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
$ 



$ oc get mc |grep 12m$
rendered-master-5861a738deb2dc2af9a0b78ca14bdc0f            3ad3a836ba89556b422454b4e5614dbd031ea3a3   2.2.0             12m
rendered-worker-ad5345eeacf011c37d9aa14aaf366303            3ad3a836ba89556b422454b4e5614dbd031ea3a3   2.2.0             12m
$ 
$ oc get mcp
NAME     CONFIG                                             UPDATED   UPDATING   DEGRADED   MACHINECOUNT   READYMACHINECOUNT   UPDATEDMACHINECOUNT   DEGRADEDMACHINECOUNT
master   rendered-master-945d021c2ea5c0704633b5ca04cdcb38   False     True       False      3              2                   2                     0
worker   rendered-worker-ad5345eeacf011c37d9aa14aaf366303   True      False      False      3              3                   3                     0
$ 
$ oc get nodes -o wide 
NAME                                       STATUS   ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE                                                       KERNEL-VERSION                CONTAINER-RUNTIME
ip-10-0-1-18.eu-west-1.compute.internal    Ready    worker   57m   v1.16.2   10.0.1.18     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-1-21.eu-west-1.compute.internal    Ready    master   65m   v1.16.2   10.0.1.21     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-2-128.eu-west-1.compute.internal   Ready    master   65m   v1.16.2   10.0.2.128    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-2-217.eu-west-1.compute.internal   Ready    worker   57m   v1.16.2   10.0.2.217    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-3-176.eu-west-1.compute.internal   Ready    master   65m   v1.16.2   10.0.3.176    <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
ip-10-0-3-34.eu-west-1.compute.internal    Ready    worker   57m   v1.16.2   10.0.3.34     <none>        Red Hat Enterprise Linux CoreOS 43.81.202002110953.0 (Ootpa)   4.18.0-147.5.1.el8_1.x86_64   cri-o://1.16.3-19.dev.rhaos4.3.git6c1f4bd.el8
$ 
$ oc get mcp
NAME     CONFIG                                             UPDATED   UPDATING   DEGRADED   MACHINECOUNT   READYMACHINECOUNT   UPDATEDMACHINECOUNT   DEGRADEDMACHINECOUNT
master   rendered-master-5861a738deb2dc2af9a0b78ca14bdc0f   True      False      False      3              3                   3                     0
worker   rendered-worker-ad5345eeacf011c37d9aa14aaf366303   True      False      False      3              3                   3                     0
$ 
$ oc adm upgrade
info: An upgrade is in progress. Working towards 4.3.2: 84% complete

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
$ oc adm upgrade
Cluster version is 4.3.2

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
$ 
$ 

=========================================================================================================================================================
============== below is the behaviour when https proxy was not set in install config despite config stating otherwise====================================
=========================================================================================================================================================

[ec2-user@ip-10-0-0-161 ~]$ oc adm upgrade
Cluster version is 4.3.1

warning: Cannot display available updates:
  Reason: RemoteFailed
  Message: Unable to retrieve available updates: Get https://api.openshift.com/api/upgrades_info/v1/graph?arch=amd64&channel=stable-4.3&id=efe7c267-48a0-42cf-a23c-89f2c31889f2&version=4.3.1: dial tcp 18.207.44.243:443: connect: connection timed out

[ec2-user@ip-10-0-0-161 ~]$ 
[ec2-user@ip-10-0-0-161 ~]$ oc get -o yaml proxy/cluster
apiVersion: config.openshift.io/v1
kind: Proxy
metadata:
  creationTimestamp: "2020-02-25T18:19:12Z"
  generation: 1
  name: cluster
  resourceVersion: "434"
  selfLink: /apis/config.openshift.io/v1/proxies/cluster
  uid: 3abe2af0-e507-40bd-a54b-5829cc0ab5aa
spec:
  httpProxy: http://10.0.0.161:3128
  noProxy: csa2-lab.org
  trustedCA:
    name: ""
status:
  httpProxy: http://10.0.0.161:3128
  noProxy: .cluster.local,.eu-west-1.compute.internal,.svc,10.0.0.0/16,10.128.0.0/14,127.0.0.1,169.254.169.254,172.30.0.0/16,api-int.test-cluster.dmoessne2.csa2-lab.org,csa2-lab.org,etcd-0.test-cluster.dmoessne2.csa2-lab.org,etcd-1.test-cluster.dmoessne2.csa2-lab.org,etcd-2.test-cluster.dmoessne2.csa2-lab.org,localhost
[ec2-user@ip-10-0-0-161 ~]$ 
[ec2-user@ip-10-0-0-161 ~]$ oc get machine -n openshift-machine-api 
NAME                                         PHASE     TYPE        REGION      ZONE         AGE
test-cluster-72qvd-master-0                  Running   m5.xlarge   eu-west-1   eu-west-1a   45m
test-cluster-72qvd-master-1                  Running   m5.xlarge   eu-west-1   eu-west-1b   45m
test-cluster-72qvd-master-2                  Running   m5.xlarge   eu-west-1   eu-west-1c   45m
test-cluster-72qvd-worker-eu-west-1a-7m2wc   Running   m5.xlarge   eu-west-1   eu-west-1a   41m
test-cluster-72qvd-worker-eu-west-1b-n8ljn   Running   m5.xlarge   eu-west-1   eu-west-1b   41m
test-cluster-72qvd-worker-eu-west-1c-pqhct   Running   m5.xlarge   eu-west-1   eu-west-1c   41m
[ec2-user@ip-10-0-0-161 ~]$ 
[ec2-user@ip-10-0-0-161 ~]$ oc get machinesets -n openshift-machine-api 
NAME                                   DESIRED   CURRENT   READY   AVAILABLE   AGE
test-cluster-72qvd-worker-eu-west-1a   1         1         1       1           45m
test-cluster-72qvd-worker-eu-west-1b   1         1         1       1           45m
test-cluster-72qvd-worker-eu-west-1c   1         1         1       1           45m
[ec2-user@ip-10-0-0-161 ~]$ 
[ec2-user@ip-10-0-0-161 ~]$ oc get po -A |egrep -v "Running|Completed"
NAMESPACE                                               NAME                                                                READY   STATUS      RESTARTS   AGE
[ec2-user@ip-10-0-0-161 ~]$ 


--> adding https proxy to config like so 
[ec2-user@ip-10-0-0-161 ~]$ oc edit proxy/cluster
[ec2-user@ip-10-0-0-161 ~]$ oc get -o yaml proxy/cluster
apiVersion: config.openshift.io/v1
kind: Proxy
metadata:
  creationTimestamp: "2020-02-25T18:19:12Z"
  generation: 2
  name: cluster
  resourceVersion: "38836"
  selfLink: /apis/config.openshift.io/v1/proxies/cluster
  uid: 3abe2af0-e507-40bd-a54b-5829cc0ab5aa
spec:
  httpProxy: http://10.0.0.161:3128
  httpsProxy: http://10.0.0.161:3128
  noProxy: csa2-lab.org
  trustedCA:
    name: ""
status:
  httpProxy: http://10.0.0.161:3128
  httpsProxy: http://10.0.0.161:3128
  noProxy: .cluster.local,.eu-west-1.compute.internal,.svc,10.0.0.0/16,10.128.0.0/14,127.0.0.1,169.254.169.254,172.30.0.0/16,api-int.test-cluster.dmoessne2.csa2-lab.org,csa2-lab.org,etcd-0.test-cluster.dmoessne2.csa2-lab.org,etcd-1.test-cluster.dmoessne2.csa2-lab.org,etcd-2.test-cluster.dmoessne2.csa2-lab.org,localhost
[ec2-user@ip-10-0-0-161 ~]$ 

--> it seems to work, while docu stated if no https is specified it falls back to http: https://docs.openshift.com/container-platform/4.3/installing/installing_aws/installing-aws-private.html#installation-configure-proxy_installing-aws-private 
~~~
A proxy URL to use for creating HTTPS connections outside the cluster. If this field is not specified, then httpProxy is used for both HTTP and HTTPS connections. The URL scheme must be http; https is currently not supported.
~~~

--> after specifying  ... and waiting to probagate through the cluster ....
[ec2-user@ip-10-0-0-161 ~]$ oc get co 
NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE
authentication                             4.3.1     True        False         False      79m
cloud-credential                           4.3.1     True        False         False      103m
cluster-autoscaler                         4.3.1     True        False         False      94m
console                                    4.3.1     True        False         False      3m17s
dns                                        4.3.1     True        False         False      99m
image-registry                             4.3.1     True        False         False      4m50s
ingress                                    4.3.1     True        False         False      4m49s
insights                                   4.3.1     True        False         False      100m
kube-apiserver                             4.3.1     True        False         False      99m
kube-controller-manager                    4.3.1     True        False         False      97m
kube-scheduler                             4.3.1     True        False         False      96m
machine-api                                4.3.1     True        False         False      99m
machine-config                             4.3.1     True        False         False      98m
marketplace                                4.3.1     True        False         False      3m48s
monitoring                                 4.3.1     True        False         False      85m
network                                    4.3.1     True        False         False      98m
node-tuning                                4.3.1     True        False         False      4m20s
openshift-apiserver                        4.3.1     True        False         False      97m
openshift-controller-manager               4.3.1     True        False         False      99m
openshift-samples                          4.3.1     True        False         False      93m
operator-lifecycle-manager                 4.3.1     True        False         False      99m
operator-lifecycle-manager-catalog         4.3.1     True        False         False      99m
operator-lifecycle-manager-packageserver   4.3.1     True        False         False      2m44s
service-ca                                 4.3.1     True        False         False      100m
service-catalog-apiserver                  4.3.1     True        False         False      95m
service-catalog-controller-manager         4.3.1     True        False         False      95m
storage                                    4.3.1     True        False         False      95m
[ec2-user@ip-10-0-0-161 ~]$ 
[ec2-user@ip-10-0-0-161 ~]$ oc adm upgrade
Cluster version is 4.3.1

No updates available. You may force an upgrade to a specific release image, but doing so may not be supported and result in downtime or data loss.
[ec2-user@ip-10-0-0-161 ~]$ 

--> change channel to candidate (in this case via oc edit clusterversion) 
and wating a bit until the check is done:

[ec2-user@ip-10-0-0-161 ~]$ oc adm upgrade
Cluster version is 4.3.1

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
[ec2-user@ip-10-0-0-161 ~]$ oc adm upgrade --to-latest 
Updating to latest version 4.3.2
[ec2-user@ip-10-0-0-161 ~]$ oc adm upgrade 
info: An upgrade is in progress. Working towards 4.3.2: downloading update

Updates:

VERSION IMAGE
4.3.2   quay.io/openshift-release-dev/ocp-release@sha256:cadf53e7181639f6cc77d2430339102db2908de330210c1ff8c7a7dc1cb0e550
[ec2-user@ip-10-0-0-161 ~]$ 
=========================================================================================================================================================
============== above is the behaviour when https proxy was not set in install config despite config stating otherwise====================================
=========================================================================================================================================================

