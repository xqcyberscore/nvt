###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_mult_xss_vuln_jul14.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# MantisBT Multiple Cross-Site Scripting Vulnerabilities -01 July14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804676");
  script_version("$Revision: 7585 $");
  script_cve_id("CVE-2013-1810", "CVE-2013-0197");
  script_bugtraq_id(57468, 57456);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-07-14 11:59:38 +0530 (Mon, 14 Jul 2014)");
  script_name("MantisBT Multiple Cross-Site Scripting Vulnerabilities -01 July14");

  tag_summary =
"This host is installed with MantisBT and is prone to multiple cross-site
scripting vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws exists due to,
- Input passed via the 'name' parameter to manage_proj_cat_add.php script when
creating a category is not properly sanitised in core/summary_api.php script
before being used.
- Input passed to the 'match_type' POST parameter in bugs/search.php script is
not properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser and
the server.

Impact Level: Application";

  tag_affected =
"MantisBT version 1.2.12, prior versions may also be affected.";

  tag_solution =
"Upgrade to MantisBT version 1.2.13 or later.
For updates refer to http://www.mantisbt.org/download.php";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/51853");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81394");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=15384");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=15373");
  script_xref(name : "URL" , value : "http://hauntit.blogspot.de/2013/01/en-mantis-bug-tracker-1212-persistent.html");
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

if(version_is_equal(version:manVer, test_version:"1.2.12"))
{
  security_message(port:manPort);
  exit(0);
}
