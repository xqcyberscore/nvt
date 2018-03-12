###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_privilege_escalation_vuln_feb14_lin.nasl 9070 2018-03-09 12:37:39Z cfischer $
#
# Oracle Java SE Privilege Escalation Vulnerability Feb 2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108424");
  script_version("$Revision: 9070 $");
  script_cve_id("CVE-2014-1876");
  script_bugtraq_id(65568);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-03-09 13:37:39 +0100 (Fri, 09 Mar 2018) $");
  script_tag(name:"creation_date", value:"2014-02-13 12:54:10 +0530 (Thu, 13 Feb 2014)");
  script_name("Oracle Java SE Privilege Escalation Vulnerability Feb 2014 (Linux)");

  script_tag(name: "summary" , value:"This host is installed with Oracle Java
  SE and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to some error in the
  'unpacker::redirect_stdio' function within 'unpack.cpp'.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a local
  attacker to use a symlink attack against the '/tmp/unpack.log' file to overwrite
  arbitrary files.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Oracle Java SE 7 update 51 and prior on
  Linux");

  script_tag(name:"solution", value:"Upgrade to version 8 update 5 or 7 update 55,
  or higher, For updates refer to www.oracle.com/index.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2014/q1/242");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(jreVer =~ "^(1\.7)")
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.51"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "8 update 5 or 7 update 55");
    security_message(data:report);
    exit(0);
  }
}

exit(99);