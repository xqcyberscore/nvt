###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_esc_priv_jun_2016.nasl 8218 2017-12-21 14:14:04Z cfischer $
#
# Panda Small Business Protection - Privilege Escalation June 2016 (Windows) 
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:pandasecurity:panda_small_business_protection";

tag_impact = "Successful exploitation will let the attacker replace the affected binary file
with a malicious binary which will be executed with SYSTEM privileges.

Impact level: System.";

tag_affected = "Panda Small Business Protection (16.1.2)";

tag_insight = "As the USERS group has write permissions over the folder where the PSEvents.exe
process is located, it is possible to execute malicious code as Local System.";

tag_solution = "Install Panda Hotfix for this vulnerability.
http://www.pandasecurity.com/uk/support/card?id=100053";

tag_summary = "This host is running Panda Small Business Protection and is prone to Privilege
Escalation Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107085");
  script_version("$Revision: 8218 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 15:14:04 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-11-18 09:18:47 +0100 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Panda Small Business Protection - Privilege Escalation June 2016 (Windows)");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40020/");
  script_tag(name:"qod", value:"30");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/SmallBusinessProtection/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "solution_type", value: "VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers  = infos['version'];
path  = infos['location'];

if( version_is_equal( version:vers, test_version:"16.01.02" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( data:report );
  exit( 0 );
}

exit( 99 );