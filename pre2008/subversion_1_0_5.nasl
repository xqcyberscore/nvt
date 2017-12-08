# OpenVAS Vulnerability Test
# $Id: subversion_1_0_5.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Subversion SVN Protocol Parser Remote Integer Overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
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

tag_solution = "Upgrade to version 1.0.5 or newer";

tag_summary = "A remote overflow exists in Subversion. svnserver fails to validate 
svn:// requests resulting in a heap overflow. With a specially 
crafted request, an attacker can cause arbitrary code execution 
resulting in a loss of integrity.";

# ref: ned <nd@felinemenace.org>

if(description)
{
 script_id(12284);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10519);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2004-0413");
 script_xref(name:"OSVDB", value:"6935");
 script_xref(name:"GLSA", value:"GLSA 200406-07");
 script_xref(name:"SuSE", value:"SUSE-SA:2004:018");

 name = "Subversion SVN Protocol Parser Remote Integer Overflow";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/subversion");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}



# start check
# mostly horked from MetaSploit Framework subversion overflow check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/OpenVASr0x ) ");

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);

if (! r)
	exit(0);

#display(r);

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*"))
{
	security_message(port);
}

close(soc);
exit(0);
