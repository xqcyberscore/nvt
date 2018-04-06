# OpenVAS Vulnerability Test
# $Id: interscan_vw_cgi.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: InterScan VirusWall Remote Configuration Vulnerability
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
#
# Copyright:
# Copyright (C) 2001 INTRANODE
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_solution = "don't connect the management interface directly to the Internet";

tag_summary = "The management interface used with the Interscan VirusWall 
uses several cgi programs that may allow a malicious user to remotely 
change the configuration of the server without any authorization using 
maliciously constructed querystrings.";

#### REGISTER SECTION ####

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10733");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2579);
 script_cve_id("CVE-2001-0432");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

#Name used in the client window.

name = "InterScan VirusWall Remote Configuration Vulnerability";
script_name(name);






#Summary appearing in the tooltips, only one line. 

summary="Check if the remote Interscan is vulnerable to remote reconfiguration.";

#Test it among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

#Copyright stuff

script_copyright("Copyright (C) 2001 INTRANODE");


 
#Category in which script must be stored.

family="Web application abuses";
script_family(family);


script_dependencies("http_version.nasl");


#optimization, stop here if either no web service was found by find_service.nasl plugin or no port 80 was open.

script_require_ports(80, "Services/www");
 
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
exit(0);
}




#### ATTACK CODE SECTION ####



include("http_func.inc");
include("http_keepalive.inc");
#search web port in knowledge database

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


request = http_get(item:"/interscan/cgi-bin/FtpSave.dll?I'm%20Here", port:port);
receive = http_keepalive_send_recv(port:port, data:request);

signature = "These settings have been saved";

if (signature >< receive)
{
 security_message(port);
}

