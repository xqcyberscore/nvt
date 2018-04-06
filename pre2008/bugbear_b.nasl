# OpenVAS Vulnerability Test
# $Id: bugbear_b.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Bugbear.B web backdoor
#
# Authors:
# StrongHoldNet
# Modifications by rd:
#  -> Try every web server, not just port 81
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
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

tag_summary = "Your system seems to be infected by the Bugbear.B virus
(its backdoor has been detected on port 81).

More information: http://www.f-secure.com/v-descs/bugbear_b.shtml";

tag_solution = "Use your favorite antivirus to disinfect your
system. Standalone disinfection tools also exist :
ftp://ftp.f-secure.com/anti-virus/tools/f-bugbr.zip";

# Ref: http://www.f-secure.com/v-descs/bugbear_b.shtml

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11707");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Bugbear.B web backdoor");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Malware");
 script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 81);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:81);

url = string('/%NETHOOD%/');
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) && "Microsoft Windows Network" >< buf) security_message(port);
