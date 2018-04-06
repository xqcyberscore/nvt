# OpenVAS Vulnerability Test
# $Id: jrun_getdir.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Allaire JRun directory browsing vulnerability
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# Changes by gareth@sensepost.com (SensePost) :
# * Test all discovered directories for jsp bug
#
# Copyright:
# Copyright (C) 2001 Felix Huber
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

tag_summary = "Allaire JRun 3.0/3.1 under a Microsoft IIS 4.0/5.0 platform has a
problem handling malformed URLs. This allows a remote user to browse
the file system under the web root (normally \inetpub\wwwroot).

Under Windows NT/2000(any service pack) and IIS 4.0/5.0:
- JRun 3.0 (all editions)
- JRun 3.1 (all editions)


Upon sending a specially formed request to the web server, containing
a '.jsp' extension makes the JRun handle the request. Example:

http://www.victim.com/%3f.jsp

This vulnerability allows anyone with remote access to the web server
to browse it and any directory within the web root.";

tag_solution = ">From Macromedia Product Security Bulletin (MPSB01-13)
http://www.allaire.com/handlers/index.cfm?ID=22236&Method=Full

Macromedia recommends, as a best practice, turning off directory
browsing for the JRun Default Server in the following applications:
- Default Application (the application with '/' mapping that causes
  the security problem)

- Demo Application
  Also, make sure any newly created web application that uses the '/'
  mapping has directory browsing off.

The changes that need to be made in the JRun Management Console or JMC:

- JRun Default Server/Web Applications/Default User Application/File
  Settings/Directory Browsing Allowed set to FALSE.
- JRun Default Server/Web Applications/JRun Demo/File Settings/
  Directory Browsing Allowed set to FALSE.

Restart the servers after making the changes and the %3f.jsp request
should now return a 403 forbidden. When this bug is fixed, the request
(regardless of directory browsing setting) should return a '404 page
not found'.

The directory browsing property is called [file.browsedirs]. Changing
the property via the JMC will cause the following changes:
JRun 3.0 will write [file.browsedirs=false] in the local.properties
file. (server-wide change)
JRun 3.1 will write [file.browsedirs=false] in the webapp.properties
of the application.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10814");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1510");
 script_bugtraq_id(3592);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Allaire JRun directory browsing vulnerability";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

 script_copyright("This script is Copyright (C) 2001 Felix Huber");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "DDI_Directory_Scanner.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

dirs = make_list_unique("/", "/images", "/html", cgi_dirs(port:port));

foreach d (dirs)
{
 req = http_get(item:string(d+"/%3f.jsp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL) exit(0);

 if(egrep(pattern:"Index of /", string:r)||(egrep(pattern:"Directory Listing", string:r))) ddir += d + '\n';
}
if(ddir != NULL)
{
    report = string("
Allaire JRun 3.0/3.1 under a Microsoft IIS 4.0/5.0 platform has a
problem handling malformed URLs. This allows a remote user to browse
the file system under the web root (normally inetpubwwwroot).

Upon sending a specially formed request to the web server, containing
a '.jsp' extension makes the JRun handle the request.
Example:

http://www.victim.com/%3f.jsp

The following directories were found to be browsable:
" +ddir + " ");
    security_message(port:port, data:report);

}
