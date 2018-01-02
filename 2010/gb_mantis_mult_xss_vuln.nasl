##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_mult_xss_vuln.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# MantisBT Multiple Cross-site scripting Vulnerabilities
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

tag_impact = "Successful exploitation will allow attackers to conduct cross-site scripting
  attacks.
  Impact Level: Application.";
tag_affected = "MantisBT version prior to 1.2.3";

tag_insight = "Multiple flaws exist in the application which allow remote authenticated
  attackers to inject arbitrary web script or HTML via:
  (1) A plugin name, related to 'manage_plugin_uninstall.php'
  (2) An 'enumeration' value
  (3) A 'String' value of a custom field, related to 'core/cfdefs/cfdef_standard.php'
  (4) project
  (5) category name to 'print_all_bug_page_word.php' or
  (6) 'Summary field', related to 'core/summary_api.php'";
tag_solution = "Upgrade to MantisBT version 1.2.3 or later
  For updates refer to http://www.mantisbt.org/download.php";
tag_summary = "This host is running MantisBT and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801603");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_cve_id("CVE-2010-3303", "CVE-2010-3763");
  script_bugtraq_id(43604);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MantisBT Multiple Cross-site scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12231");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12232");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12234");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12238");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12309");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/changelog_page.php?version_id=111");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
mantisPort = get_http_port(default:80);
if(!get_port_state(mantisPort)){
  exit(0);
}

## GET the version from KB
mantisVer = get_version_from_kb(port:mantisPort,app:"mantis");

if(mantisVer != NULL)
{
  ## Check for the  MantisBT version
  if(version_is_less(version:mantisVer, test_version:"1.2.3")){
    security_message(mantisPort);
  }
}
