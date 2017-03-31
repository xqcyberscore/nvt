# OpenVAS Vulnerability Test
# $Id: cfengine_trans_packet_buff_overrun.nasl 3395 2016-05-27 12:54:51Z antu123 $
# Description: cfengine CFServD transaction packet buffer overrun vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "Cfengine is running on this remote host.

This version is prone to a stack-based buffer overrun vulnerability. 
An attacker, exploiting this flaw, would need network access to the
server as well as the ability to send a crafted transaction packet
to the cfservd process.  A successful exploitation of this flaw
would lead to arbitrary code being executed on the remote machine
or a loss of service (DoS).";

tag_solution = "Upgrade to at least 1.5.3-4, 2.0.8 or most recent 2.1 version.";

# Ref: Nick Cleaton <nick@cleaton.net>

if(description)
{
 script_id(14317);
 script_version("$Revision: 3395 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-27 14:54:51 +0200 (Fri, 27 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8699);
 script_cve_id("CVE-2003-0849");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 name = "cfengine CFServD transaction packet buffer overrun vulnerability";
 script_name(name);
 

 summary = "check for cfengine flaw based on its version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");

 family = "Gain a shell remotely";
 
 script_family(family);
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);

version=get_kb_item("cfengine/version");
if (version)
{
 	if (egrep(pattern:"(1\.[0-4]\.|1\.5\.[0-2]|1\.5\.3-[0-3]|2\.(0\.[0-7]|1\.0a[0-9][^0-9]))", string:version))
  		security_message(port);
}

