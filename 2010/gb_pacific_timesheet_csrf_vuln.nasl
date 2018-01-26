###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pacific_timesheet_csrf_vuln.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Pacific Timesheet Cross-Site Request Forgery Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to perform unauthorized
  actions.
  Impact Level: Application";
tag_affected = "Pacific Timesheet version 6.74 build 363.";
tag_insight = "The flaw is due to improper validation of user-supplied input.
  A remote attacker could exploit this vulnerability to perform cross-site
  request forgery by tricking a logged in administrator into visiting a
  malicious web site or link to perform unauthorized actions.";
tag_solution = "Update to version 6.75 or later.
  For updates refer to http://www.pacifictimesheet.com/";
tag_summary = "This host is running Pacific Timesheet and is prone to cross-site
  request forgery vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800181");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2111");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Pacific Timesheet Cross-Site Request Forgery Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39951");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58934");
  script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/05/pacific-timesheet-674-cross-site.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pacific_timesheet_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

pacificTSPort = get_http_port(default:80);
if(!pacificTSPort){
  exit(0);
}

## Get Pacific Timesheet from KB
pacificTSVer = get_kb_item("www/" + pacificTSPort + "/pacificTimeSheet/Ver");
pacificTSVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pacificTSVer);

if(pacificTSVer[1] != NULL)
{
  ## Check for version 6.74 build 363.
  if(version_is_equal(version:pacificTSVer[1], test_version:"6.74.363")) {
    security_message(pacificTSPort);
  }
}
