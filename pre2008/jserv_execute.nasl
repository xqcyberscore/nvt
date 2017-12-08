# OpenVAS Vulnerability Test
# $Id: jserv_execute.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Oracle Jserv Executes outside of doc_root
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
# based on a script written by Hendrik Scholz <hendrik@scholz.net> 
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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

tag_summary = "Detects Vulnerability in the execution of JSPs outside
doc_root.

A potential security vulnerability has been discovered in
Oracle JSP releases 1.0.x through 1.1.1 (in
Apache/Jserv). This vulnerability permits access to and
execution of unintended JSP files outside the doc_root in
Apache/Jserv. For example, accessing
http://www.example.com/a.jsp//..//..//..//..//..//../b.jsp
will execute b.jsp outside the doc_root instead of a.jsp
if there is a b.jsp file in the matching directory.

Further, Jserv Releases 1.0.x - 1.0.2 have additional
vulnerability:

Due to a bug in Apache/Jserv path translation, any
URL that looks like:
http://host:port/servlets/a.jsp, makes Oracle JSP
execute 'd:\servlets\a.jsp' if such a directory
path actually exists. Thus, a URL virtual path, an
actual directory path and the Oracle JSP name
(when using Oracle Apache/JServ) must match for
this potential vulnerability to occur.

Vulnerable systems:
Oracle8i Release 8.1.7, iAS Release version 1.0.2
Oracle JSP, Apache/JServ Releases version 1.0.x - 1.1.1";

tag_solution = "Upgrade to OJSP Release 1.1.2.0.0, available on Oracle
Technology Network's OJSP web site.";

if(description)
{
 script_id(10925);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-0307");
 
 name = "Oracle Jserv Executes outside of doc_root";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl",  "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
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
str = http_get_cache(item:"/", port:port);
if(ereg(pattern:".*apachejserv/1\.(0|1\.[0-1][^0-9])",string:str))
      security_message(port);
