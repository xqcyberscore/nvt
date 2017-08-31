###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_bof_vuln01_feb14_win.nasl 34938 2014-02-03 18:02:51Z Feb$
#
# Oracle MySQL Client Remote Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804082";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-0001");
  script_bugtraq_id(65298);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-03 18:02:51 +0530 (Mon, 03 Feb 2014)");
  script_name("Oracle MySQL Client Remote Buffer Overflow Vulnerability (Windows)");

  tag_summary =
"This host is installed with Oracle MySQL Client and is prone to remote buffer
overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an user-supplied input is not properly validated when handling
server versions in client/mysql.cc.";

  tag_impact =
"Successful exploitation will allow attackers to manipulate certain data and
cause a DoS (Denial of Service).

Impact Level: Application";

  tag_affected =
"Oracle MySQL version 5.5.34 and earlier.";

  tag_solution =
"Upgrade to MySQL version 5.5.35 or later,
For Updates refer to http://www.mysql.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.12135");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1029708");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
clientVer = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("MySQL Server" >< appName)
  {
    ## Get the Installed Path
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc) continue;

    clientVer = fetch_file_version(sysPath: insloc, file_name:"bin\mysql.exe");

    if(clientVer && clientVer =~ "^(5\.5)")
    {
      if(version_in_range(version:clientVer, test_version:"5.5", test_version2:"5.5.34"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
