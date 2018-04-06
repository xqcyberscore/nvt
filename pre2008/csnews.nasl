# OpenVAS Vulnerability Test
# $Id: csnews.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: CSNews.cgi vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "The CSNews.cgi exists on this webserver. Some versions of this file 
are vulnerable to remote exploit.

An attacker may make use of this file to gain access to
confidential data or escalate their privileges on the Web
server.";

tag_solution = "remove it from the cgi-bin or scripts directory.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11726");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4994);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2002-0923");
 script_name("CSNews.cgi vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 script_family("Web application abuses");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("IIS/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

flag = 0;

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  if(is_cgi_installed_ka(item:string(dir, "/csNews.cgi"), port:port)) {
    flag = 1;
    break;
  } 
}
 
if (flag) security_message(port);
