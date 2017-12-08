# OpenVAS Vulnerability Test
# $Id: robotftp.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: RobotFTP DoS
#
# Authors:
# Audun Larsen <larsen@xqus.com>
# Modified by rd to use get_ftp_banner() and be solely banner-based
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
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

tag_summary = "The remote host seems to be running RobotFTP.

RobotFTP server has been reported prone to a denial of service vulnerability.
The issue presents itself when certain commands are sent to the service,
before authentication is negotiated.

The following versions of RobotFTP are vulnerable:
RobotFTP RobotFTP Server 1.0
RobotFTP RobotFTP Server 2.0 Beta 1
RobotFTP RobotFTP Server 2.0";

tag_solution = "Use a different FTP server";

if(description)
{
 script_id(12082);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9729);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "RobotFTP DoS";

 script_name(name);




 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 Audun Larsen");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 banner  = get_ftp_banner(port:port);
 if ( ! banner ) exit(0);
 if ( egrep(pattern:"^220.*RobotFTP", string:banner) )
 {
  security_message(port);
  exit(0);
 }
}
