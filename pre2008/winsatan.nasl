# OpenVAS Vulnerability Test
# $Id: winsatan.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WinSATAN
#
# Authors:
# Julio César Hernández <jcesar@inf.uc3m.es>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2000 Julio César Hernández
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

tag_summary = "WinSATAN is installed. 

This backdoor allows anyone to partially take control
of the remote system.

An attacker may use it to steal your password or prevent
your system from working properly.";

tag_solution = "use RegEdit, and find 'RegisterServiceBackUp'
in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
The value's data is the path of the file.
If you are infected by WinSATAN, then
the registry value is named 'fs-backup.exe'.

Additional Info : http://online.securityfocus.com/archive/75/17508
Additional Info : http://online.securityfocus.com/archive/75/17663";


if(description)
{
 script_id(10316);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "WinSATAN";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_probe");
 
 
 script_copyright("This script is Copyright (C) 2000 Julio César Hernández");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(999);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
if(get_port_state(999))
{
soc = open_sock_tcp(999);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"uyhw6377w", pass:"bhw32qw"))security_message(999);
 close(soc);
}
}
