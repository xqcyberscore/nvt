###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_53396.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Symantec Web Gateway 'l' Parameter Cross Site Scripting Vulnerability
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

tag_summary = "Symantec Web Gateway is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103484";
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
 script_oid(SCRIPT_OID); 
 script_bugtraq_id(53396);
 script_version ("$Revision: 6720 $");
 script_cve_id("CVE-2012-0296");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Symantec Web Gateway 'l' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53396");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/web-gateway");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-05-07 14:02:06 +0200 (Mon, 07 May 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_web_gateway_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("symantec_web_gateway/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = string(dir, "/spywall/timer.php?d=0&l=0'<script>alert(/openvas-xss-test/)</script>&profile=0"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
