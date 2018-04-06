# OpenVAS Vulnerability Test
# $Id: ultraseek_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Ultraseek Web Server Detect
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
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

tag_summary = "Ultraseek Web Server is running on this host. 
Ultraseek has been known to contain security vulnerabilities ranging from 
Buffer Overflows to Cross Site Scripting issues.";

tag_solution = "Make sure you are running the latest version of the Ultraseek
Web Server or disable it if you do not use it.

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeamwords=Ultraseek";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10791");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1866, 874);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-1999-0996", "CVE-2000-1019");
 
 name = "Ultraseek Web Server Detect";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 family = "General";
 script_family(family);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Ultraseek/banner");
 script_require_ports("Services/www", 8765);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# useless message. ultraseek_dos.nasl already do this check
exit(0);

#
# The script code starts here
#
 include("http_func.inc");

 port = get_http_port(default:8765);
 if (!port) exit(0);

 if (get_port_state(port))
 {
   banner = get_http_banner(port:port);
   if(!banner)exit(0);
   if ("Server: Ultraseek" >< banner)
   {
    security_message(port);
   }
 }
