##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_webserver_code_exec_vuln.nasl 9984 2018-05-28 14:36:22Z cfischer $
#
# nginx Arbitrary Code Execution Vulnerability
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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execution arbitrary
  code.

  Impact Level: Application");
  script_tag(name : "affected" , value : "nginx versions 0.5.x, 0.6.x, 0.7.x to 0.7.65 and 0.8.x to 0.8.37");
  script_tag(name : "insight" , value : "The null bytes are allowed in URIs by default (their presence is indicated
  via a variable named zero_in_uri defined in ngx_http_request.h). Individual
  modules have the ability to opt-out of handling URIs with null bytes.");
  script_tag(name : "solution" , value : "Upgrade to nginx 0.7.66 or 0.7.38 or later,
  For updates refer to http://nginx.org");
  script_tag(name : "summary" , value : "This host is running nginx and is prone to arbitrary code execution
  vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803194");
  script_version("$Revision: 9984 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 16:36:22 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2013-04-22 15:03:39 +0530 (Mon, 22 Apr 2013)");
  script_name("nginx Arbitrary Code Execution Vulnerability");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24967/");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/multiple/nginx-06x-arbitrary-code-execution-nullbyte-injection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nginx/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less_equal(version:vers, test_version:"0.7.65") ||
   version_in_range(version:vers, test_version:"0.8", test_version2:"0.8.37"))
{
  security_message(port);
  exit(0);
}
