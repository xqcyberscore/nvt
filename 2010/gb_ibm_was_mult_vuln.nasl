###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply Fix Pack 13 for version 7.0 (7.0.0.13) or later,
  http://www-01.ibm.com/support/docview.wss?uid=swg27014463

  *****
  NOTE : Ignore this warning, if above workaround has been applied.
  *****";

tag_impact = "Successful exploitation will let attackers to conduct Cross-site scripting
  attacks and cause a Denial of Service.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 7.0 before 7.0.0.13.";
tag_insight = "- A cross-site scripting vulnerability exists in the administrative console
    due to improper filtering on input values.
  - A cross-site scripting vulnerability exists in the Integrated Solution
    Console due to improper filtering on input values.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

CPE = 'cpe:/a:ibm:websphere_application_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801647");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-0784", "CVE-2010-4220");
  script_bugtraq_id(44875);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/41722");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2595");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

## Check for IBM WebSphere Application Server versions 7.0 before 7.0.0.13
if(version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.12")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'7.0.0.12' );
  security_message(port:0, data:report);
}
