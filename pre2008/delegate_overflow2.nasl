# OpenVAS Vulnerability Test
# $Id: delegate_overflow2.nasl 4715 2016-12-08 12:26:47Z mime $
# Description: Delegate Multiple Overflows
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Changes by Tenable Network Security:
#  - POP3 check
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.17599");
 script_version("$Revision: 4715 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-08 13:26:47 +0100 (Thu, 08 Dec 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2005-0861");
 script_bugtraq_id(12867);

 script_name("Delegate Multiple Overflows");

 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Gain a shell remotely");
 script_dependencies("http_version.nasl","find_service.nasl");
 script_require_ports("Services/http_proxy", 8080, "Services/pop3", 110);
 script_tag(name : "solution" , value : "Upgrade to version 8.10.3 of this product");
 script_tag(name : "summary" , value :"The remote host is running Delegate, a multi-application proxy.

The remote version of this software is vulnerable to multiple
remote buffer overflow vulnerabilities which may allow an attacker
to execute arbitrary code on the remote host.

This problem may allow an attacker to gain a shell on this computer." );
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( get_port_state(port) )
{
 banner = get_pop3_banner(port:port);
 if ( banner )
 {
  if ( egrep(pattern:"^\+OK Proxy-POP server \(Delegate/([0-7]\..*|8\.([0-9]\..*|10\.[0-2][^0-9])) by", string:banner) )
	security_message(port);
  exit(0);
 }
}

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

if(get_port_state(port))
{
   banner = get_http_banner(port:port);
   if ( banner )
   {
   #Server: DeleGate/8.11.1
   serv = strstr(banner, "Server");
   if(ereg(pattern:"^Server:.*DeleGate/([0-7]\.|8\.([0-9]\.|10\.[0-2][^0-9]))", string:serv, icase:TRUE))
     security_message(port);
   }
}
