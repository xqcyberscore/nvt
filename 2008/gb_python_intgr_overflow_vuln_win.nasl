###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_intgr_overflow_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Python Multiple Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Remote exploitation will allow execution of arbitrary code via large number
  of integer values to modules.
  Impact Level: Application";
tag_affected = "Python 2.5.2 on Windows.";
tag_insight = "The flaw exists due the the way it handles large integer values in the
  tabsize arguments as input to expandtabs methods (string_expandtabs and
  nicode_expandtabs) in stringobject.c and unicodeobject.c.";
tag_solution = "Upgrade to Python 2.5.5 or later.
  For updates refer to http://www.python.org/";
tag_summary = "This host has Python installed and is prone to integer overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800056");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5031");
  script_name("Python Multiple Integer Overflow Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!(get_kb_item("SMB/WindowsVersion"))){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach entry (registry_enum_keys(key:key))
{
  pyName = registry_get_sz(key:key + entry, item:"DisplayName");
  if("Python" >< pyName)
  {
    pyVer = eregmatch(pattern:"[0-9.]+", string:pyName);
    if(pyVer != NULL)
    {
      if(version_is_equal(version:pyVer[0], test_version:"2.5.2")){
        security_message(0);
      }
    }
    exit(0);
  }
}
