# OpenVAS Vulnerability Test
# $Id: webcalendar_info_disclosure.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WebCalendar User Account Enumeration Disclosure Issue
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_solution = "Upgrade to WebCalendar 1.0.4 or later.

CVSS Base Score : 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)";

tag_summary = "The remote web server is affected by an information disclosure issue. 

Description:

The version of WebCalendar on the remote host is prone to a user
account enumeration weakness in that in response to login attempts it
returns different error messages depending on whether the user exists
or the password is invalid.";


if(description)
{
 script_id(80021);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_bugtraq_id(17853);
 script_xref(name:"OSVDB", value:"25280");
 script_cve_id("CVE-2006-2247");

 name = "WebCalendar User Account Enumeration Disclosure Issue";
 script_name(name);
 

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 
 family = "Web application abuses";
 script_family(family);

 script_dependencies("webcalendar_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("webcalendar/installed");

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/433053/30/0/threaded");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/436263/30/0/threaded");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?group_id=3870&release_id=423010");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/login.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if ("webcalendar_session=deleted; expires" >< res && '<input name="login" id="user"' >< res)
  {
    postdata=string(
	  "login=openvas", unixtime(), "&",
	  "password=openvas"
    );
    req = string(
   "POST ", url, " HTTP/1.1\r\n",
	 "Host: ", get_host_name(), "\r\n",
	 "Content-Type: application/x-www-form-urlencoded\r\n",
	 "Content-Length: ", strlen(postdata), "\r\n",
	 "\r\n",
	 postdata
    );

    #display("req='", req, "'.\n");
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    #display("res='", res, "'.\n");
    if (res == NULL) exit(0);

    if ("Invalid login: no such user" >< res) {
	security_message(port);
    }
  }
}
