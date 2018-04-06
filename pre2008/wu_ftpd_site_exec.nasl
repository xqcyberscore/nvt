# OpenVAS Vulnerability Test
# $Id: wu_ftpd_site_exec.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: wu-ftpd SITE EXEC vulnerability
#
# Authors:
# Alexis de Bernis <alexisb@nessus.org>
# changes by rd :
# - rely on the banner if we could not log in
# - changed the description to include a Solution:
#
# Copyright:
# Copyright (C) 2000 A. de Bernis
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

tag_summary = "The remote FTP server does not properly sanitize the argument of
the SITE EXEC command.
It may be possible for a remote attacker
to gain root access.";

tag_solution = "Upgrade your wu-ftpd server (<= 2.6.0 are vulnerable)
or disable any access from untrusted users (especially anonymous).";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10452");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1387, 2240, 726);
 script_xref(name:"IAVA", value:"2000-a-0004");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2000-0573", "CVE-1999-0997");
 
 name = "wu-ftpd SITE EXEC vulnerability";
 
 script_name(name);
              
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");

 
 script_copyright("This script is Copyright (C) 2000 A. de Bernis");
                  
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl",
 "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/wuftpd");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");



port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if(soc)
{
 if(login)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = string("SITE EXEC %p \r\n");
  send(socket:soc, data:c);
  b = recv(socket:soc, length:6);
  if(b == "200-0x") security_message(ftpport);
  quit = string("QUIT\r\n");
  send(socket:soc, data:quit);
  r = ftp_recv_line(socket:soc);
  close(soc);
  exit(0);
  }
  else {
  	close(soc);
	soc = open_sock_tcp(ftpport);
	}
 }
  if(!soc)soc = open_sock_tcp(ftpport);
  if(!soc)exit(0);
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*FTP server.*[vV]ersion wu-((1\..*)|(2\.[0-5]\..*)|(2\.6\.0)).*",
  	 string:r)){
	 data = string(
"You are running a version of wu-ftpd which is older or\n",
"as old as version 2.6.0.\n",
"These versions do not sanitize the user input properly\n",
"and allow an intruder to execute arbitrary code through\n",
"the command SITE EXEC.\n\n",
"*** OpenVAS did not log into this server\n",
"*** so it could not determine whether the option SITE\n",
"*** EXEC was activated or not, so this message may be\n",
"*** a false positive\n\n",
"Solution: upgrade to wu-ftpd 2.6.1");
	 security_message(port:ftpport, data:data);
	 }
}
