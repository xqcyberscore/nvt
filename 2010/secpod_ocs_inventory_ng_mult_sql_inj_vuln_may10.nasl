##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_mult_sql_inj_vuln_may10.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# OCS Inventory NG Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to to view, add, modify
  or delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "OCS Inventory NG prior to 1.02.3";

tag_insight = "The flaws are due to the error in the 'index.php' page, which fails to
  properly varify the user supplied input via the 'search' form for the various
  inventory fields and via the All softwares search form for the 'Software name'
  field.";
tag_solution = "Upgrade to OCS Inventory NG version 1.02.3
  For updates refer to http://www.ocsinventory-ng.org/";
tag_summary = "This host is running OCS Inventory NG and is prone to multiple SQL
  injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902059");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-1733");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("OCS Inventory NG Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38311");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55873");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
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

ocsPort = get_http_port(default:80);
if(!get_port_state(ocsPort)){
  exit(0);
}

ocsVer = get_kb_item("www/"+ ocsPort + "/OCS_Inventory_NG");
if(isnull(ocsVer)){
  exit(0);
}

ocsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ocsVer);
if(ocsVer[1] != NULL)
{
  ## Check the OCS_Inventory_NG version less than 1.02.3
  if(version_is_less(version:ocsVer[1], test_version:"1.02.3")){
    security_message(ocsPort);
  }
}
