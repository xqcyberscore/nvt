# OpenVAS Vulnerability Test
# $Id: sunftpd_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: SunFTP Buffer Overflow
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
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

tag_summary = "Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.";

tag_solution = "Switching to another FTP server, SunFTP is discontinued.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11373");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1638);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2000-0856");
 name = "SunFTP Buffer Overflow";

 script_name(name);

 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul"); 
 script_family("FTP");


 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");

 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
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
if(!get_port_state(port))exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  if("SunFTP b9"><banner) {
    report = "
 Summary:

Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: Switching to another FTP server, SunFTP is discontinued.";

  security_message(port:port, data:report);
  }
 }

 exit(0);
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
  # make sure the FTP server exists
  send(socket:soc, data:string("help\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b)exit(0);
  if("SunFTP" >!< b)exit(0);
  close(soc);
  
  soc = open_sock_tcp(port);
  longstring=string(crap(2200));
  send(socket:soc, data:string(longstring, "\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b){
	security_message(port);
	exit(0);
  } else {
	ftp_close(socket:soc);
  }
}
