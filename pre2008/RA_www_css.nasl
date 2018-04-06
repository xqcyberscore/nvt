# OpenVAS Vulnerability Test
# $Id: RA_www_css.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: RemotelyAnywhere Cross Site Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

tag_summary = "The remote RemotelyAnywhere web interface is vulnerable to a cross site 
scripting issue.

Description :

A vulnerability in RemotelyAnywhere's web interface allows a remote
attacker to inject malicious text into the login screen, this can
be used by an attacker to make the user do things he would otherwise
not do (for example, change his password after a successful login to
some string provided by the malicious text).";

tag_solution = "Upgrade to the newest version of this software";

# From: Oliver Karow [Oliver.Karow@gmx.de]
# Subject: Remotely Anywhere Message Injection Vulnerability
# To: bugtraq@securityfocus.com
# Date: Thursday 11/12/2003 12:36

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11950");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9202);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  name = "RemotelyAnywhere Cross Site Scripting"; 
  script_name(name);
 
 
  summary = "Detect RemotelyAnywhere www css";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  family = "Web application abuses";
  script_family(family);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RemotelyAnywhere/banner");
  script_require_ports("Services/www", 2000,2001);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2001);
if (! port) exit(0);

banner = get_http_banner(port : port);
if (! banner) exit(0);

# display("banner: ", banner, "\n");

if (ereg(pattern:"Server: *RemotelyAnywhere", string:banner))
{
  req = http_get(item:"/default.html?logout=asdf&reason=Please%20set%20your%20password%20to%20ABC123%20after%20login", port:port);
  res = http_keepalive_send_recv(data:req, port:port, bodyonly:1);
  if ( res == NULL ) exit(0);
#  display("req: ", req, "\n");

  if ("Please set your password to ABC123 after login" >< res)
  {
   	security_message(port);
	exit(0);
  }
}
