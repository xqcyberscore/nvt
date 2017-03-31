# OpenVAS Vulnerability Test
# $Id: csnews.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: CSNews.cgi vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "The CSNews.cgi exists on this webserver. Some versions of this file 
are vulnerable to remote exploit.

An attacker may make use of this file to gain access to
confidential data or escalate their privileges on the Web
server.";

tag_solution = "remove it from the cgi-bin or scripts directory.";

if(description)
{
 script_id(11726);
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4994);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2002-0923");
 
 
 name = "CSNews.cgi vulnerability";
 script_name(name);
 


 summary = "Checks for the csnews.cgi file";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("IIS/banner");
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
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/csNews.cgi"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
 
if (flag) security_message(port);
