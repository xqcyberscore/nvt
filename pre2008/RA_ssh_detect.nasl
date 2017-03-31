# OpenVAS Vulnerability Test
# $Id: RA_ssh_detect.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: RemotelyAnywhere SSH detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Broken link deleted
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "The RemotelyAnywhere SSH server is running on this system.
According to NAVCIRT crackers love this management tool.

If you installed it, ignore this warning. If not, your machine is 
compromised by an attacker.";

if(description)
{
  script_id(10921);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 3362 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RemotelyAnywhere SSH detection");
 

 
  summary = "Detect RemotelyAnywhere SSH server";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  family = "Malware";
  script_family(family);
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22); 
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

port = get_kb_item("Services/ssh");
if (! port) port = 22;

if(!get_port_state(port))exit(0);


banner = get_kb_item("SSH/banner/" + port);
if (! banner) exit(0);

if (ereg(pattern:'SSH-[0-9.-]+[ \t]+RemotelyAnywhere', string:banner))
{
  log_message(port);
}

# TBD: check default account administrator / remotelyanywhere
