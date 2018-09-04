###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln01_apr14.nasl 11207 2018-09-04 07:22:57Z mmartin $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities-01 April2014
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
CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804432");
  script_version("$Revision: 11207 $");
  script_cve_id("CVE-2014-2406", "CVE-2014-2408");
  script_bugtraq_id(66889, 66884);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 09:22:57 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-18 12:12:27 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-01 April2014");


  script_tag(name:"summary", value:"This host is installed with Oracle Database Server and is prone to multiple
unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Get the installed version with the help of tnslsnr service and check it is
vulnerable or not.");
  script_tag(name:"insight", value:"Multiple flaws exist in Core RDBMS component, no further information
available at this moment.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose sensitive
information, manipulate certain data, and compromise a vulnerable
system.

Impact Level: System/Application");
  script_tag(name:"affected", value:"Oracle Database Server 11.1.0.7, 11.2.0.3, 11.2.0.4, and 12.1.0.1");
  script_tag(name:"solution", value:"Apply patches from below link,
http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html

*****
NOTE: Ignore this warning if above mentioned patch is installed.
*****");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57311");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_mandatory_keys("OracleDatabaseServer/installed");
  script_dependencies("oracle_tnslsnr_version.nasl");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!dbport = get_app_port(cpe:CPE))exit(0);

if(!get_tcp_port_state(dbport))exit(0);

if(!ver = get_app_version(cpe:CPE, port:dbport))exit(0);

if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)")
{
  if(version_in_range(version:ver, test_version:"11.2.0.3", test_version2:"11.2.0.4") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7")){
    security_message(dbport);
  }
}
