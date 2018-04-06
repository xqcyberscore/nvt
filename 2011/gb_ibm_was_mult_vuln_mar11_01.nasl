###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln_mar11_01.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities 01 - March 2011
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to obtain sensitive information
  and cause a denial of service.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1.0.x before 6.1.0.35 and
  7.x before 7.0.0.15";
tag_insight = "- The Administrative Scripting Tools component, when tracing is enabled,
    places wsadmin command parameters into the 'wsadmin.traceout' and
    'trace.log' files, which allows local users to obtain potentially
    sensitive information by reading these files.
  - A double free error which allows remote backend IIOP servers to cause a
    denial of service by rejecting IIOP requests at opportunistic time
    instants.
  - The Security component allows remote authenticated users to cause a denial
    of service by using a Lightweight Third-Party Authentication (LTPA) token
    for authentication.
  - The Security component does not properly delete AuthCache entries upon a
    logout, which might allow remote attackers to access the server by
    leveraging an unattended workstation.";
tag_solution = "Upgrade to IBM WebSphere Application Server version 6.1.0.35 or 7.0.0.15,
  http://www-01.ibm.com/support/docview.wss?uid=swg24028405
  http://www-01.ibm.com/support/docview.wss?uid=swg24028875";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801862");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1310", "CVE-2011-1313", "CVE-2011-1319", "CVE-2011-1320");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities 01 - March 2011");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

## Check for IBM WebSphere Application Server versions
if(version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.34") ||
   version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.14")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:'6.1.0.35/7.0.0.15' );
  security_message(port:0, data:report);
}
