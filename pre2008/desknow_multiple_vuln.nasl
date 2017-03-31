# OpenVAS Vulnerability Test
# $Id: desknow_multiple_vuln.nasl 3301 2016-05-12 12:56:09Z benallard $
# Description: DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# chewkeong@security.org.sg
# 2005-02-03 00:34
# DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16308");
 script_version("$Revision: 3301 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-12 14:56:09 +0200 (Thu, 12 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0332");
 script_bugtraq_id(12421);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities");
 script_summary("Checks for the presence of an old version of DeskNow");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Upgrade to DeskNow version 2.5.14 or newer");
 script_tag(name : "summary" , value : "DeskNow Mail and Collaboration Server is a full-featured and integrated 
 mail and instant messaging server, with webmail, secure instant 
 messaging, document repository, shared calendars, address books, 
 message boards, web-publishing, anti-spam features, Palm and 
 PocketPC access and much more.

 A directory traversal vulnerability was found in DeskNow webmail 
 file attachment upload feature that may be exploited to upload 
 files to arbitrary locations on the server. A malicious webmail 
 user may upload a JSP file to the script directory of the server, 
 and executing it by requesting the URL of the upload JSP file. 
 A second directory traversal vulnerability exists in the document 
 repository file delete feature. This vulnerability may be exploited 
 to delete arbitrary files on the server.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_app");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

function check(loc)
{

 if(loc == "/") loc = "";

 req = http_get(item:string(loc, "/index.html"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( egrep(pattern:"DeskNow&reg; (0\.|1\.|2\.[0-4]\.|2\.5\.[0-9][^0-9]|2\.5\.1[0-3])", string:r) ) 
 { 
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/desknow", cgi_dirs(port:port)))
{
 check(loc:dir);
}

exit(99);