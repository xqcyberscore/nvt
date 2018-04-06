# OpenVAS Vulnerability Test
# $Id: aspdev_imgtag.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ASP-DEv XM Forum IMG Tag Script Injection Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote web server contains an ASP script which is vulnerable to a
cross site scripting issue.

Description :

The remote host appears to be running the ASP-DEV XM Forum.

There is a flaw in the remote software which may allow anyone
to inject arbitrary HTML and script code through the BBCode IMG tag
to be executed in a user's browser within the context of the affected
web site.";

tag_solution = "Unknown at this time.";

# Fixed by Tenable:
#  - Improved description
#  - Adjusted version regex.
#  - Streamlined code.

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18357");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1008");
 script_bugtraq_id(12958);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("ASP-DEv XM Forum IMG Tag Script Injection Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:dir +"/default.asp", port:port);
  if ( res == NULL ) continue;
  if ( res =~ '<a href="http://www\\.asp-dev\\.com">Powered by ASP-DEv XM Forums RC [123]<' ) {
    security_message(port);
    exit(0);
  }
}
