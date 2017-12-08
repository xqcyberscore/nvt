# OpenVAS Vulnerability Test
# $Id: goaheadwebserver_source_disclosure.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: GoAhead WebServer Script Source Code Disclosure
#
# Authors:
# Ferdy Riphagen 
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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

tag_summary = "A vulnerable version of GoAhead Webserver is running on the
remote host.

Description :

GoAhead Webserver is installed on the remote system.
It's an open-source webserver, which is capable of 
hosting ASP pages, and installation on multiple operating
systems. 

The version installed is vulnerable to Script Source Code
Disclosure, by adding extra characters to the URL. Possible 
characters are %00, %5C, %2F.";

tag_solution = "Upgrade to GoAhead WebServer 2.1.8 or a newer release.";

if (description) {
 script_id(2000099); 
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_cve_id("CVE-2002-1603");
 script_bugtraq_id(9239);
 script_xref(name:"OSVDB", value:"13295");

 name = "GoAhead WebServer Script Source Code Disclosure";
 script_name(name);

 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("GoAhead-Webs/banner");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/goahead-adv3.txt");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/975041");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function GetFileExt(file) {
 ret = split(file, sep: '.');
 return ret;
}

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Server: GoAhead-Webs" >!< banner) exit(0);

# Possible default file which still could be available.
file[0] = "/treeapp.asp";

# Below options could possible create false-positives.
 file[1] = "/default.asp";

 if ("HTTP/1.0 302" && "Location:" >< banner) {
  redirect = egrep(pattern:"^Location:", string:banner);
  rfile = ereg_replace(pattern:"Location: http:\/\/+[^/]+", string:redirect, replace:"", icase:1); 
 
  # See if the file is really asp.
  ret = GetFileExt(file:rfile);
  if(!isnull(ret)) {
   if (ereg(pattern:"asp", string:ret[1], icase:1)) { 
    file[2] = chomp(rfile);
   }
  }
 }


for (n = 0; file[n]; n++) {
 # Server doesn't support keepalives.
 soc = http_open_socket(port);
 if (!soc) exit(0); 

 req = string("GET ", file[n], "%5C HTTP/1.1", "\r\n",
              "Host: ", get_host_name(), "\r\n\r\n");
 send(socket:soc, data:req);
 
 res = http_recv(socket:soc);
 http_close_socket(soc);
 
 if ('<% write(HTTP_AUTHORIZATION); %>' >< res ||
    ('<%' >< res && ('%>' >< res))) { 
  security_message(port);
  exit(0);
 }
}
