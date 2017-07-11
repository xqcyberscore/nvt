###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_trace_req_dos_vuln.nasl 6376 2017-06-20 10:00:24Z teissa $
#
# Apache Traffic Server HTTP TRACE Request Remote DoS Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805128");
  script_version("$Revision: 6376 $");
  script_cve_id("CVE-2014-10022");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-06-20 12:00:24 +0200 (Tue, 20 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-01-21 11:00:56 +0530 (Wed, 21 Jan 2015)");
  script_name("Apache Traffic Server HTTP TRACE Request Remote DoS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Traffic
  Server is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Flaw is due to an improper handling HTTP
  TRACE requests with a 'Max-Forwards' header value of '0'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the traffic_manager process.

  Impact Level: Application.");

  script_tag(name:"affected", value:"Apache Traffic Server version 5.1.x
  before 5.1.2");

  script_tag(name:"solution", value:"Upgrade to version 5.1.2 or later,
  For updates refer to http://trafficserver.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "URL" , value : "https://issues.apache.org/jira/browse/TS-3223");
  script_xref(name: "URL" , value : "http://mail-archives.apache.org/mod_mbox/trafficserver-users/201412.mbox/thread");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web Servers");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");
  script_require_ports("Services/http_proxy", 8080, 3128, 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
appPort = "";
appVer = "";

## Get Application HTTP Port
if(!appPort = get_app_port(cpe:CPE)){
  error_message(data:"Not able to get Apache Traffic Server Port");
  exit(-1);
}

## Get Apache Traffic Server version
if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  error_message(data:"Not able to get Apache Traffic Server Version");
  exit(-1);
}

if(appVer =~ "^(5\.1)")
{
  ## Check for version
  if(version_in_range(version:appVer, test_version:"5.1.0", test_version2:"5.1.1"))
  {
    report = 'Installed version: ' + appVer + '\n' + 'Fixed version: 5.1.2 \n';
    security_message(port:appPort, data:report);
    exit(0);
  }
}
