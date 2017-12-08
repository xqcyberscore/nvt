# OpenVAS Vulnerability Test
# $Id: qpopper2.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: qpopper options buffer overflow
#
# Authors:
# Thomas reinke <reinke@securityspace.com>
# Changes by rd: description moved, bugfix
#
# Copyright:
# Copyright (C) 2002 Thomas Reinke
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

tag_solution = "Upgrade to the latest version, or disable
processing of user option files.";

tag_summary = "The remote qpopper server, according to its banner, is
running version 4.0.3 or version 4.0.4.  These versions
are vulnerable to a buffer overflow if they are configured
to allow the processing of a user's ~/.qpopper-options file.
A local user can cause a buffer overflow by setting the
bulldir variable to something longer than 256 characters.

*** This test could not confirm the existence of the
*** problem - it relied on the banner being returned.";

if(description)
{
 script_id(10948);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2811);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2001-1046");
 name = "qpopper options buffer overflow";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 
 script_copyright("This script is Copyright (C) 2002 Thomas Reinke");
 
 family = "Buffer overflow";
 
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/pop3", 110);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
  
    if(ereg(pattern:".*Qpopper.*version (4\.0\.[34]).*", string:banner, icase:TRUE))
    {
	security_message(port);
    }
}
exit(0);
