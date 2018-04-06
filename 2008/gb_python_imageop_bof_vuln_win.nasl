###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_imageop_bof_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Python Imageop Module imageop.crop() BOF Vulnerability (Windows)
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
  of integer values to crop module, which leads to a buffer overflow
  (Segmentation fault).
  Impact Level: Application";
tag_affected = "Python 1.5.2 to 2.5.1 on Windows";
tag_insight = "The flaw exists due the the way module imageop.crop() handles the arguments
  as input in imageop.c file.";
tag_solution = "Upgrade to Python 2.5.2
  http://www.python.org/";
tag_summary = "This host has Python installed and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800052");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4864");
  script_bugtraq_id(31976);
  script_name("Python Imageop Module imageop.crop() BOF Vulnerability (Windows)");
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
      if(version_in_range(version:pyVer[0], test_version:"1.5.2",
                          test_version2:"2.5.1")){
        security_message(0);
      }
    }
    exit(0);
  }
}
