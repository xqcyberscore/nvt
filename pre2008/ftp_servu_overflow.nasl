# OpenVAS Vulnerability Test
# $Id: ftp_servu_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Serv-U FTP Server SITE CHMOD Command Stack Overflow Vulnerability
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
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

tag_summary = "The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the SITE CHMOD
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.";

tag_solution = "Upgrade to Serv-U FTP Server version 4.2 or later.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.12037");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2111", "CVE-2004-2533");
 script_bugtraq_id(9483, 9675);
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 
 name = "Serv-U FTP Server SITE CHMOD Command Stack Overflow Vulnerability";
 
 script_name(name);
	     

		 
 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 
 
 script_copyright("This script is Copyright (C) 2004 Astharot");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl", "secpod_ftp_anonymous.nasl");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-01/0249.html");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2004-02/0881.html");
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || "Serv-U FTP Server " >!< banner ) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");
if (!login || safe_checks()) {

 data = "
The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the SITE CHMOD
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

** OpenVAS only check the version number in the server banner
** To really check the vulnerability, disable safe_checks

Solution: Upgrade to Serv-U Server 4.2.0 or newer";

 banner = get_ftp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"Serv-U FTP Server v([0-3]|4\.[0-1])\.", string:banner))security_message(port: port, data: data); 
 exit(0);
}


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a", length:2000);
 req = string("SITE CHMOD 0666  ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
 if(!r)
 {
  security_message(port);
  exit(0);
 }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
 close(soc);
}
