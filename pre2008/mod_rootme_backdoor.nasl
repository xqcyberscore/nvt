# OpenVAS Vulnerability Test
# $Id: mod_rootme_backdoor.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: Apache mod_rootme Backdoor
#
# Authors:
# Noam Rathaus and upgraded by Alexei Chicheev for mod_rootme v.0.3 detection 
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection
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

tag_summary = "The remote system appears to be running the mod_rootme module,
this module silently allows a user to gain a root shell access
to the machine via HTTP requests.";

tag_solution = "- Remove the mod_rootme module from httpd.conf/modules.conf
- Consider reinstalling the computer, as it is likely to have been 
compromised by an intruder";

if(description)
{
  script_id(13644);
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  name = "Apache mod_rootme Backdoor";
  script_name(name);
 
 
  summary = "Detect mod_rootme Backdoor";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection");

  family = "Malware";
  script_family(family);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("apache/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (! port) exit(0);

banner = get_http_banner(port:port);
if ( ! banner || "Apache" >!< banner ) exit(0);

if(!get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

soc = open_sock_tcp(port);
if (soc)
{
 # Syntax for this Trojan is essential... normal requests won't work...
 # We need to emulate a netcat, slow sending, single line each time, unlike HTTP that can
 # receive everything as a block
 send(socket:soc, data:string("GET root HTTP/1.0\n",
                              "Host: ", get_host_name(),"\r\n"));
 sleep(1);
 send(socket:soc, data:string("\n"));
 sleep(1);
 res_vx = recv(socket:soc, length:1024);
 if ( ! res_vx ) exit(0);
 send(socket:soc, data:string("id\r\n",
                              "Host: ", get_host_name(), "\r\n"));
 res = recv(socket:soc, length:1024);
 if (res == NULL) exit(0);
 if (ereg(pattern:"^uid=[0-9]+\(root\)", string:res) && ereg(pattern:"^rootme-[0-9].[0-9] ready", string:res_vx))
 {
  send(socket:soc, data:string("exit\r\n",
                               "Host: ", get_host_name(), "\r\n")); # If we don't exit we can cause Apache to crash
  security_message(port:port);
 }
 close(soc);
}

