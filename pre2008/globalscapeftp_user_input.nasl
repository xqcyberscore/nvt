# OpenVAS Vulnerability Test
# $Id: globalscapeftp_user_input.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: GlobalSCAPE Secure FTP Server User Input Overflow
#
# Authors:
# Gareth Phillips - SensePost (www.sensepost.com)
# changes by Tenable:
#  - Fixed regex
#
# Copyright:
# Copyright (C) 2005 SensePost
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

tag_summary = "The remote host is running GlobalSCAPE Secure FTP Server.

GlobalSCAPE Secure FTP Server 3.0.2 and prior versions are affected by a buffer overflow 
due to mishandling the user-supplied input. 

An attacker would first need to authenticate to the server before they can execute 
arbitrary commands.";

tag_solution = "Upgrade to newest release of this software";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18627");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1415");
 script_bugtraq_id (13454);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 name = "GlobalSCAPE Secure FTP Server User Input Overflow";
 script_name(name);




 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2005 SensePost");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}




#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

ftpbanner = get_ftp_banner(port:port);
if ( ftpbanner && egrep(pattern:"^220 GlobalSCAPE Secure FTP Server \(v. 3(.0|\.0\.[0-2])\)",string:ftpbanner) )security_message(port);
