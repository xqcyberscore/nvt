###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_jsf_info_disclosure_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 8.x before 8.0.0.1";
tag_insight = "The flaw is caused by improper handling of requests in 'JSF' applications.
  A remote attacker could gain unauthorized access to view files on the host.";
tag_solution = "Apply the latest Fix Pack (8.0.0.1 or later) or APAR PM45992
  http://www-01.ibm.com/support/docview.wss?uid=swg21474220";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801998");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-1368");
  script_bugtraq_id(50463);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-03 18:00:39 +0530 (Thu, 03 Nov 2011)");
  script_name("IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70168");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM45992");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg24030916");

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
if(version_is_equal(version: vers, test_version: "8.0.0.0")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'8.0.0.1' );
  security_message(port:0, data:report);
}
