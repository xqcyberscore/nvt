# OpenVAS Vulnerability Test
# $Id: iis5_sample_path.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS 5.0 Sample App reveals physical path of web root
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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

tag_summary = "A sample application shipped with IIS 5.0 discloses 
the physical path of the web root. An attacker can use this information 
to make more focused attacks.";

tag_solution = "Always remove sample applications from productions servers.
In this case, remove the entire /iissamples folder.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10573");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 name = "IIS 5.0 Sample App reveals physical path of web root";
 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp", port:port);
if(res)security_message(port);
