###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_view_issues_page_dos_vuln.nasl 5067 2017-01-23 16:23:44Z cfi $
#
# MantisBT 'View Issues' Page Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804650");
  script_version("$Revision: 5067 $");
  script_cve_id("CVE-2013-1883");
  script_bugtraq_id(58626);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-23 17:23:44 +0100 (Mon, 23 Jan 2017) $");
  script_tag(name:"creation_date", value:"2014-06-23 15:25:38 +0530 (Mon, 23 Jun 2014)");
  script_name("MantisBT 'View Issues' Page Denial of Service Vulnerability");

  tag_summary =
"This host is installed with MantisBT and is prone to Denial of Service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an error in the filter_api.php script.";

  tag_impact =
"Successful exploitation will allow remote attacker to consume all available
memory resources and cause a denial of service condition.

Impact Level: Application";

  tag_affected =
"MantisBT version 1.2.12 through 1.2.14";

  tag_solution =
"Upgrade to MantisBT version 1.2.15 or later.
For updates refer to http://www.mantisbt.org/download.php";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/83347");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=15573");
  script_summary("Check the version MantisBT is vulnerable or not");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
manPort = "";
manVer = "";

## get the port
if(!manPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Check the port status
if(!get_port_state(manPort)){
  exit(0);
}

## Get the version
if(!manVer = get_app_version(cpe:CPE, port:manPort)){
  exit(0);
}

if(version_in_range(version:manVer, test_version:"1.2.12", test_version2:"1.2.14"))
{
  security_message(port:manPort);
  exit(0);
}
