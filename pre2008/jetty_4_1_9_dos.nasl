# OpenVAS Vulnerability Test
# $Id: jetty_4_1_9_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Jetty < 4.2.19 Denial of Service
#
# Authors:
# Sarju Bhagat <sarju@westpoint.ltd.uk>
# Fixes by Tenable:
#   - added CVE and OSVDB xrefs.
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

tag_summary = "The remote host is running a version of Jetty which is older than
4.2.19.  The version is vulnerable to a unspecified denial of service.";

tag_solution = "Upgrade to the latest version, or apply a patch.";

if(description)
{
 script_id(17348);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2381");
 script_bugtraq_id(9917);
 script_xref(name:"OSVDB", value:"4387");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "Jetty < 4.2.19 Denial of Service";

 script_name(name);





 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");


 script_copyright("This script is Copyright (C) 2005 Westpoint Limited");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Jetty/banner");
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
 if(!banner || "Jetty/" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Jetty/4\.([01]\.|2\.([0-9][^0-9]|1[0-8]))", string:serv))
 {
   security_message(port);
   exit(0);
 }
}
