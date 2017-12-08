# OpenVAS Vulnerability Test
# $Id: allegro_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Allegro Software RomPager 2.10 Denial of Service
#
# Authors:
# Sarju Bhagat <sarju@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2005 Westpoint Limited
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

tag_summary = "The remote host is running Allegro Software RomPager version 2.10, according
to its banner. This version is vulnerable to a denial of service when sending a
specifically crafted malformed request.";

tag_solution = "Upgrade to the latest version, or apply a patch.";

if(description)
{
 script_id(19304);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(1290);
 script_cve_id("CVE-2000-0470");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Allegro Software RomPager 2.10 Denial of Service";


 script_name(name);




 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");


 script_copyright("This script is Copyright (C) 2005 Westpoint Limited");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Allegro/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner || "Allegro" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Allegro-Software-RomPager/2\.([0-9][^0-9]|10)", string:serv))
 {
   security_message(port);
   exit(0);
 }
}
