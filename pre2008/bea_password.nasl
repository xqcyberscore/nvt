# OpenVAS Vulnerability Test
# $Id: bea_password.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: BEA WebLogic Operator/Admin Password Disclosure Vulnerability
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
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

tag_summary = "The remote web server is running WebLogic.

BEA WebLogic Server and WebLogic Express are reported prone to a vulnerability 
that may result in the disclosure of Operator or Admin passwords. An attacker 
who has interactive access to the affected managed server, may potentially 
exploit this issue in a timed attack to harvest credentials when the managed 
server fails during the boot process.";

tag_solution = "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp";

# Reference: http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp

if(description)
{
 script_id(12043);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1757");
 script_bugtraq_id(9501);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "BEA WebLogic Operator/Admin Password Disclosure Vulnerability";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 Astharot");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

sig = get_http_banner(port:port);
if ( sig && "WebLogic" >!< sig ) exit(0);

banner = get_http_banner(port:port);

if ("Temporary Patch for CR127930" >< banner) exit(0);


if (egrep(pattern:"^Server:.*WebLogic ([6-8]\..*)", string:banner))
{
  security_message(port);
}

