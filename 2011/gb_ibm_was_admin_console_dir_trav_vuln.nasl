###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_admin_console_dir_trav_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM WebSphere Application Server Administration Directory Traversal Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to read arbitrary files on the
  affected application and obtain sensitive information that may lead to
  further attacks.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1 before 6.1.0.41,
  7.0 before 7.0.0.19 and 8.0 before 8.0.0.1";
tag_insight = "The flaw is due to error in administration console which fails to
  handle certain requests. This allows remote attackers to read arbitrary
  files via a '../' (dot dot) in the URI.";
tag_solution = "Upgrade IBM WebSphere Application Server to 6.1.0.41 or 7.0.0.19 or
  8.0.0.1
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg24028875";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to directory traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801977");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-1359");
  script_bugtraq_id(49362);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IBM WebSphere Application Server Administration Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45749");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69473");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21509257");

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
if(version_is_equal(version: vers, test_version:"8.0.0.0") ||
   version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.40") ||
   version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.18")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'6.1.0.41/7.0.0.19' );
  security_message(port:0, data:report);
}
