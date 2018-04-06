# OpenVAS Vulnerability Test
# $Id: cherokee_remote_cmd.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Cherokee remote command execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to remote
command execution due to a lack of web requests sanitization,
especially shell metacharacters.

Additionally, this version fails to drop root privileges after it binds 
to listen port.

A remote attacker may submit a specially crafted web request to 
execute arbitrary command on the server with root privileges.";

tag_solution = "Upgrade to Cherokee 0.2.7 or newer";

#  Ref: GOBBLES advisory on December 29th, 2001.

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15622");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1433");
 script_bugtraq_id(3771, 3773);

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Cherokee remote command execution";

 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Cherokee/banner");
 script_require_ports("Services/www", 443);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-6])[^0-9]", string:serv))
 {
   security_message(port);
 }
