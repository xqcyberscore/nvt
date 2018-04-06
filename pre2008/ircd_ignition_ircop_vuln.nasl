# OpenVAS Vulnerability Test
# $Id: ircd_ignition_ircop_vuln.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IgnitionServer Irc operator privilege escalation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

tag_summary = "The remote host is running a version of the IgnitionServer IRC 
service which may be vulnerable to a flaw that let remote attacker
to gain elevated privileges on the system.

A remote attacker, who is an operator, can supply an unofficial command 
to the server to obtain elevated privileges and become a global IRC operator.";

tag_solution = "Upgrade to IgnitionServer 0.2.1-BRC1 or newer";

# Ref: vendor

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14388");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2553");
 script_bugtraq_id(9783);
 script_xref(name:"OSVDB", value:"4121");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 
 name = "IgnitionServer Irc operator privilege escalation vulnerability";
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 script_family("General");

 script_dependencies("find_service.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#the code

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([01]\.|2\.0).*", string:banner)) 
{
 security_message(port);
 exit(0);
}

