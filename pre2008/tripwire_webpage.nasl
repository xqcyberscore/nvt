# OpenVAS Vulnerability Test
# $Id: tripwire_webpage.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Tripwire for Webpages Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications by rd :
#	- we read www/banner/<port> first
#	- egrep()
#	- no output of the version (redundant with the server banner)
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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

tag_solution = "Modify the banner used by Apache by adding the option
'ServerTokens' to 'ProductOnly' in httpd.conf

Additional information can be found at:
http://www.securiteam.com/securitynews/5RP0L1540K.html (Web Server banner removal guide)";

tag_summary = "We detected the remote web server as running 
Tripwire for web pages under the Apache web server. This software 
allows attackers to gather sensitive information about your server 
configuration.";


if(description)
{
 script_id(10743);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Tripwire for Webpages Detection";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_probe");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 
 port = get_http_port(default:80);

 if(!get_port_state(port))exit(0);
 banner = get_http_banner(port:port);


  if (egrep(string:banner, pattern:"^Server: Apache.* Intrusion/"))
  {
   security_message(port);
  }
