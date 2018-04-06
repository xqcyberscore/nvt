###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telnet_default_credentials.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Cisco Default Telnet Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "It was possible to login into the remote host using default credentials.";
tag_solution = "Change the password as soon as possible.";

if (description)
{

 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_oid("1.3.6.1.4.1.25623.1.0.103807");
 script_version("$Revision: 9353 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2013-10-11 17:38:09 +0200 (Fri, 11 Oct 2013)");
 script_name("Cisco Default Telnet Login");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/telnet", 23);

 script_timeout(600);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 exit(0);
}


include("telnet_func.inc");
include("default_credentials.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(!get_port_state(port))exit(0);

default = try(vendor:'cisco');
if(!default)exit(0);

banner = get_telnet_banner(port:port);

if("User Access Verification" >!< banner && "cisco" >!< banner)exit(0);

foreach pw(default) {

  up = split(pw,sep:";", keep:FALSE);
  if(isnull(up[0]) || isnull(up[1]))continue;

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  user = up[0];
  pass = up[1];

  if(pass == "none")pass = "";

  send(socket:soc, data:user + '\r\n');
  ret = recv(socket:soc, length:1024);

  if("ass" >!< ret) {
    close(soc);
    sleep(1);
    continue;
  }  

  send(socket:soc, data:pass + '\r\n');
  ret = recv(socket:soc, length:1024);

  send(socket:soc, data:'show ver\r\n');

  ret = recv(socket:soc, length:4096);
  close(soc);

  if("Cisco IOS Software" >< ret || "Cisco Internetwork Operating System Software" >< ret) {

    report = 'It was possible to login as user "' + user + '" with password "' + pass + '".\n'; ;
    security_message(port:port, data:report);
    exit(0);

  }
}

exit(99);
