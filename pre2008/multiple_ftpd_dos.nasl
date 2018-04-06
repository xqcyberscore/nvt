# OpenVAS Vulnerability Test
# $Id: multiple_ftpd_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Multiple WarFTPd DoS
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2000 StrongHoldNET
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

tag_summary = "The remote WarFTPd server is running a 1.71 version.

It is possible for a remote user to cause a denial of
service on a host running Serv-U FTP Server, G6 FTP Server
or WarFTPd Server. Repeatedly submitting an 'a:/' GET or
RETR request, appended with arbitrary data,
will cause the CPU usage to spike to 100%.

Reference: http://www.securityfocus.com/bid/2698";

tag_solution = "upgrade to the latest version of WarFTPd";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10822");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2698);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 
 name = "Multiple WarFTPd DoS";
 script_name(name);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");

 
 script_copyright("This script is Copyright (C) 2000 StrongHoldNET");
                  
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

 if(("WarFTPd 1.71" >< banner))
   security_message(port);

