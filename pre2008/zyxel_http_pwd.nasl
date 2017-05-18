# OpenVAS Vulnerability Test
# $Id: zyxel_http_pwd.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Default web account on Zyxel
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
   script_oid("1.3.6.1.4.1.25623.1.0.17304");
   script_version("$Revision: 6056 $");
   script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_bugtraq_id(6671);
   script_tag(name:"cvss_base", value:"10.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_cve_id("CVE-2001-1135", "CVE-1999-0571");
   script_name("Default web account on Zyxel");
   script_category(ACT_GATHER_INFO);
   script_copyright("This script is Copyright (C) 2005 Michel Arboi");
   script_family( "Malware");
   script_dependencies("gb_get_http_banner.nasl");
   script_mandatory_keys("ZyXEL-RomPager/banner");
   script_require_ports("Services/www", 80);

   script_tag(name : "solution" , value : "Change the password immediately.");
   script_tag(name : "summary" , value : "The remote host is a Zyxel router with its default password set.");
   script_tag(name : "impact" , value : "An attacker could connect to the web interface and reconfigure it.");

   script_tag(name:"solution_type", value:"Mitigation");

   script_tag(name:"qod_type", value:"remote_vul");

   exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

host = http_host_name(port:port);
req = 'GET / HTTP/1.0\r\n' + 'Host: ' + host + '\r\n\r\n';

# Do not use http_get, we do not want an Authorization header
send(socket: soc, data: req);
h = http_recv_headers2(socket:soc);
if (h =~ "^HTTP/1\.[01] +401 ")
{ 
 http_close_socket(soc);
 soc = http_open_socket(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n');
 h = http_recv_headers2(socket:soc);
 if (h =~ "^HTTP/1\.[01] +200 ") {
   security_message(port:port);
 }
}

http_close_socket(soc);

exit(0);
