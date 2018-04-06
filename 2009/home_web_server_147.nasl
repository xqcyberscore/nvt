###############################################################################
# OpenVAS Vulnerability Test
# $Id: home_web_server_147.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Home Web Server Graphical User Interface Remote Denial Of Service Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "According to its version number, the remote version of the Home Web Server is
  prone to a denial-of-service vulnerability because it fails to adequately
  handle malformed HTTP requests.

  Attackers can exploit this issue to cause the graphical interface of
  the server to stop responding, denying service to the administrator.

  Home Web Server 1.7.1.147 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100163");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
 script_bugtraq_id(34698);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("Home Web Server Graphical User Interface Remote Denial Of Service Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("HWS/banner");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34698");
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(get_kb_item("Services/www/" + port + "/embedded" ))exit(0);

banner = get_http_banner(port:port);
if (!banner)exit(0);
if(!egrep(pattern:"Server: .*\(HWS[0-9]+\)", string:banner) ) exit(0);

version = eregmatch(pattern: "HWS([0-9]+)", string: banner);

if(version[1] == "147") {

 security_message(port:port);
 exit(0);

}  

exit(0);
