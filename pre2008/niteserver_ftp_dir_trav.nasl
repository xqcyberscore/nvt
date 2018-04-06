# OpenVAS Vulnerability Test
# $Id: niteserver_ftp_dir_trav.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: NiteServer FTP directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

tag_summary = "The remote FTP server allows anybody to switch to the 
root directory and read potentialy sensitive files.";

tag_solution = "Upgrade your FTP server";

# References:
#
# From: matrix@infowarfare.dk
# Subject: Directory traversal vulnerabilities found in NITE ftp-server version 1.83
# Date: Wed, 15 Jan 2003 13:10:46 +0100
#
# From: "Peter Winter-Smith" <peter4020@hotmail.com> 
# To: vulnwatch@vulnwatch.org, vuln@secunia.com, bugs@securitytracker.com
# Date: Wed, 06 Aug 2003 19:41:13 +0000
# Subject: Directory Traversal Vulnerability in 121 WAM! Server 1.0.4.0
#
# Vulnerable:
# NITE ftp-server version 1.83
# 121 WAM! Server 1.0.4.0

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11466");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2003-1349");
 script_bugtraq_id(6648);
 

 name = "NiteServer FTP directory traversal";
 
 script_name(name);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "FTP";
 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

if (! ftp_authenticate(socket:soc, user: "anonymous", pass: "openvas@example.org"))
{
  ftp_close(socket:soc);
  exit(0);
}
send(socket: soc, data: 'CWD\r\n');
r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (matches) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur1 = v[1];
      break;
    }
  }
}

# Loop on vulnerable patterns
dirs = make_list("\..\..\..\..\..", "/../");
foreach d (dirs)
{
send(socket: soc, data: 'CWD ' + d + '\r\n');

r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (matches) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur2 = v[1];
      break;
    }
  }
}

if (cur1 && cur2)
{
  if (cur1 != cur2)
    security_message(port);
  ftp_close(socket: soc);
  exit(0);
}

p = ftp_pasv(socket:soc);
if(p)
{
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(soc2)
  {
     send(socket:soc, data: 'LIST\r\n');
     r = ftp_recv_listing(socket:soc2);
     r = tolower(r);
     r2 = ftp_recv_line(socket: soc);
     close(soc2);
     if ("autoexec.bat" >< r || "boot.ini" >< r || "config.sys" >< r)
     {
       security_message(port);
       break;
     }
   }
}
}
ftp_close(socket: soc);
