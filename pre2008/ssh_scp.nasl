# OpenVAS Vulnerability Test
# $Id: ssh_scp.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: scp File Create/Overwrite
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

tag_summary = "You are running OpenSSH 1.2.3, or 1.2. 
 
This version has directory traversal vulnerability in scp, it allows
a remote malicious scp server to overwrite arbitrary files via a .. (dot dot) attack.";

tag_solution = "Patch and New version are available from SSH/OpenSSH.";

if(description)
{
 script_id(11339);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1742);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2000-0992");
 
 name = "scp File Create/Overwrite";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

#Looking for OpenSSH product version number 1.2 and 1.2.3	
if(ereg(pattern:".*openssh[-_](1\.2($|\.3|[^0-9])).*",string:banner, icase:TRUE))security_message(port);

if(ereg(pattern:".*ssh-.*-1\.2\.(1[0-4]|2[0-7])[^0-9]", string:banner, icase:TRUE))security_message(port);
