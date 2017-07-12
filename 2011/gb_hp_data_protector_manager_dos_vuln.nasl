###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_manager_dos_vuln.nasl 6435 2017-06-27 06:17:04Z cfischer $
#
# HP (OpenView Storage) Data Protector Manager Remote Denial of Service Vulnerability
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

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801579");
  script_version("$Revision: 6435 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-27 08:17:04 +0200 (Tue, 27 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0514");
  script_name("HP (OpenView Storage) Data Protector Manager Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15940/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0064");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=21937");

  tag_impact = "Successful exploitation will allow attackers to cause denial of
  service condition.

  Impact Level: Application.";

  tag_affected = "HP (OpenView Storage) Data Protector Manager 6.11";

  tag_insight = "The flaw is caused by an error in the RDS service (rds.exe) when
  processing malformed packets sent to port 1530/TCP, which could be exploited by
  remote attackers to crash an affected server.";

  tag_solution = "HP has not confirmed the vulnerability and software updates are unavailable.

  No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is installed with HP (OpenView Storage) Data Protector Manager and is
  prone to denial of service vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## check the version equal to 06.11
if( version_is_equal( version:vers, test_version:"06.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );