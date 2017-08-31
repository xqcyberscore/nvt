###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln01_jan14.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities-01 Jan2014
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804227";
CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2013-5764", "CVE-2013-5853");
  script_bugtraq_id(64817, 64811);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-24 14:49:13 +0530 (Fri, 24 Jan 2014)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-01 Jan2014");

  tag_summary =
"This host is installed with Oracle Database Server and is prone to multiple
information disclosure vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of tnslsnr service and check it is
vulnerable or not.";

  tag_insight =
"Multiple flaws exist in Core RDBMS component component, no further
information available at this moment.";

  tag_impact =
"Successful exploitation will allow attackers to cause denial of service
condition.

Impact Level: Application";

  tag_affected =
"Oracle Database Server version 11.1.0.7, 11.2.0.3, and 12.1.0.1
are affected";

  tag_solution =
"Apply patches from below link,
http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html

*****
NOTE: Ignore this warning if above mentioned patch is installed.
*****";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56452/");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_mandatory_keys("OracleDatabaseServer/installed");
  script_dependencies("oracle_tnslsnr_version.nasl");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialisation
dbport = "";
ver = "";

## Get Port
if(!dbport = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get Port State
if(!get_tcp_port_state(dbport))exit(0);

## Get Version
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:dbport))exit(0);

## Check for vulnerable version
if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)")
{
  if(version_is_equal(version:ver, test_version:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7"))
  {
    security_message(dbport);
  }
}
