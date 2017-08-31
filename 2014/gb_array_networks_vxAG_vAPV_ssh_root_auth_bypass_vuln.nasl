###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_array_networks_vxAG_vAPV_ssh_root_auth_bypass_vuln.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Array Networks vxAG/xAPV Authentication Bypass Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804417";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_bugtraq_id(66299);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-20 12:13:13 +0530 (Thu, 20 Mar 2014)");
  script_name("Array Networks vxAG/xAPV Authentication Bypass Vulnerabilities");

  tag_summary = "This host is running Array Networks vxAG/xAPV and is prone to
authentication bypass vulnerabilities.";

  tag_vuldetect =
"Send a default SSH credentials and check whether it is possible to login to
the target machine";

  tag_insight =
"Multiple flaws are due to
 - The program using insecure world writable permissions for the
   '/ca/bin/monitor.sh' file.
 - The 'mfg' account has a password of 'mfg' and the 'sync' account has a
   password of 'click1', which is publicly known and documented.
 - If a remote attacker has explicit knowledge of the SSH keys they can
   potentially gain privileged access to the device.";

  tag_impact =
"Successful exploitation will allow attacker to gain unauthorized root
access to affected devices and completely compromise the devices.

Impact Level: System/Application";

  tag_affected =
"Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances";

  tag_solution =
"No Solution is available as of 20th March, 2014. Information regarding this
issue will be updated once the solution details are available. For more
information refer to http://www.arraynetworks.com ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125761");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}


include("ssh_func.inc");

userName = "mfg";
pwd = "mfg";
qdPort = "";
qdSoc = "";
loginCheck = "";

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

## try to login
loginCheck = ssh_login (socket:qdSoc, login:userName, password:pwd, pub:NULL, priv:NULL, passphrase:NULL );
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
