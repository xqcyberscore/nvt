###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blue_coat_reporter_49482.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Blue Coat Reporter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "Blue Coat Reporter is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files within the context of the Web server. Information harvested may
aid in launching further attacks.

Blue Coat Reporter versions prior to 9.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103246");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-08 15:23:37 +0200 (Thu, 08 Sep 2011)");
 script_bugtraq_id(49482);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Blue Coat Reporter Directory Traversal Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_blue_coat_reporter_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49482");
 script_xref(name : "URL" , value : "http://www.bluecoat.com/products/reporter/index.html");
 script_xref(name : "URL" , value : "http://www.bluecoat.com");
 script_xref(name : "URL" , value : "https://kb.bluecoat.com/index?page=content&id=SA60");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"blue_coat_reporter")) {

  if("Build" >< vers) {
    version = split(vers,sep:" Build ",keep:FALSE);
    if(isnull(version[0]))exit(0);
  } 

  if(version_is_less(version: version[0], test_version: "9.3.1.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
