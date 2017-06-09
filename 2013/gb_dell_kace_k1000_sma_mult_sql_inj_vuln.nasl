###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_mult_sql_inj_vuln.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# Dell KACE K1000 SMA Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803735";
CPE = "cpe:/a:dell:x_dellkace";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2014-1671");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-12 20:18:38 +0530 (Mon, 12 Aug 2013)");
  script_name("Dell KACE K1000 SMA Multiple SQL Injection Vulnerabilities");

 tag_summary =
"This host is running Dell KACE K1000 Systems Management Appliance and is prone
to multiple SQL injection vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Dell KACE K1000 SMA with the help of detect NVT
and check the version is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to asset.php, asset_type.php, metering.php, mi.php,
replshare.php, kbot.php, history_log.php and service.php scripts are not
properly sanitizing user-supplied input.";

  tag_impact =
"Successful exploitation will allow remote attackers to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure of
arbitrary data.";

  tag_affected =
"Dell KACE K1000 Systems Management Appliance version 5.4.70402";

  tag_solution =
"Upgrade to latest version of Dell KACE K1000 SMA or Apply the patch,
For updates refer to http://www.kace.com/products/systems-management-appliance ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27039");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jul/194");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_kace_k1000_sma_detect.nasl");
  script_mandatory_keys("X-DellKACE/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vers = "";
port = 0;

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Get Dell KACE K1000 Systems Management Appliance version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if(vers)
{
  if(version_is_less(version:vers, test_version:"5.5"))
  {
    report = 'Installed Version: ' + vers + '\nFixed Version:     5.5';
    security_message(port, data:report);
    exit(0);
  }
}
