# OpenVAS Vulnerability Test
# $Id: vqServer_admin_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: vqServer administrative port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- solution
#	- script id
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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

tag_summary = "vqSoft's vqServer administrative port is open. Brute force guessing of the 
username/password is possible, and a bug in versions 1.9.9 and below 
allows configuration file retrieval remotely.

For more information, see:
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html";

tag_solution = "close this port for outside access.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10354");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1610);
 script_cve_id("CVE-2000-0766");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("vqServer administrative port");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 script_family("Service detection");
 
 script_require_ports("Services/vqServer-admin", 9090);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item( "Services/vqServer-admin" );
if( ! port ) port = 9090;
if( ! get_port_state( port ) ) exit( 0 );

banner = http_get_cache( item:"/", port:port );

if( ( "Server: vqServer" >< banner ) && ( "WWW-Authenticate: Basic realm=/" >< banner ) ) {
  res = strstr(banner, "Server: ");
  sub = strstr(res, string("\n"));
  res = res - sub;
  res = res - "Server: ";
  res = res - "\n";
   
  banner = string("vqServer version is : ");
  banner = banner + res;
  security_message(port:port, data:banner);
}

exit( 0 );