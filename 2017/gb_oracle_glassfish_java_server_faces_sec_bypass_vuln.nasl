###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_java_server_faces_sec_bypass_vuln.nasl 5978 2017-04-19 12:01:36Z antu123 $
#
# Oracle GlassFish Server 'Java Server Faces' Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810747");
  script_version("$Revision: 5978 $");
  script_cve_id("CVE-2017-3626");
  script_bugtraq_id(97896);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-19 14:01:36 +0200 (Wed, 19 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-19 13:45:58 +0530 (Wed, 19 Apr 2017)");
  script_name("Oracle GlassFish Server 'Java Server Faces' Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Oracle GlassFish Server
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified errors in
  the Java Server Faces sub-component.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  users to unauthorized read access to a subset of Oracle GlassFish Server 
  accessible data.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle GlassFish Server versions 3.1.2");

  script_tag(name:"solution", value:"Apply patches from below link,
  http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");


  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2017verbose-3236619.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
dbPort = "";
dbVer = "";

## Get port
if(!dbport = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!dbVer = get_app_version(cpe:CPE, port:dbPort)){
  exit(0);
}

## Check for vulnerable version
if(dbVer =~ "^(3\.)")
{
  if(version_is_equal(version:dbVer, test_version:"3.1.2"))
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:dbPort);
    exit(0);
  }
}
