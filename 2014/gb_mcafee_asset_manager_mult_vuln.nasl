###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_asset_manager_mult_vuln.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# McAfee Asset Manager Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804428";
CPE = "cpe:/a:mcafee:asset_manager";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2014-2587", "CVE-2014-2588");
  script_bugtraq_id(66302);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-17 11:25:02 +0530 (Thu, 17 Apr 2014)");
  script_name("McAfee Asset Manager Multiple Vulnerabilities");

  tag_summary =
"This host is running McAfee Asset Manager and is prone to directory traversal
and SQL injection vulnerabilities.";

  tag_vuldetect =
"Get the installed version of McAfee Asset Manager with the help of detect NVT
and check the version is vulnerable or not.";

  tag_insight =
"The flaws are due to,
- The '/servlet/downloadReport' script not properly sanitizing user input,
  specifically path traversal style attacks supplied via the 'reportFileName'
  GET parameter.
- The /jsp/reports/ReportsAudit.jsp script not properly sanitizing
  user-supplied input to the 'user' POST parameter.";

  tag_impact =
"Successful exploitation will allow attackers to disclose potentially sensitive
information and inject or manipulate SQL queries in the back-end database,
allowing for the manipulation or disclosure of arbitrary data

Impact Level: Application";

  tag_affected =
"McAfee Asset Manager version 6.6";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32368");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125775");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Mar/325");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_asset_manager_detect.nasl");
  script_mandatory_keys("McAfee/Asset/Manager/installed");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
mwgPort = "";
mwgVer = "";

## Get Application HTTP Port
if(!mwgPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
mwgVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:mwgPort);
if(!mwgVer){
  exit(0);
}

if(version_is_equal(version:mwgVer, test_version:"6.6"))
{
  security_message(port:mwgPort);
  exit(0);
}
