###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4011179.nasl 7689 2017-11-08 05:46:44Z teissa $
#
# Microsoft Lync 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4011179)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811923");
  script_version("$Revision: 7689 $");
  script_cve_id("CVE-2017-11786");
  script_bugtraq_id(101156);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 06:46:44 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-11 09:14:12 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Lync 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4011179)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011179");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to error when Skype for
  Business fails to properly handle specific authentication requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited this vulnerability to steal an authentication hash 
  that can be reused elsewhere. The attacker could then take any action that the 
  user had permissions for, causing possible outcomes that could vary between 
  users.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Lync 2013 Service Pack 1 (32-bit)

  Microsoft Lync 2013 Service Pack 1 (64-bit)");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4011179");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4011179");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Installed");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
lyncPath = "";
commVer = "";

## Check for Microsoft Lync 2013
if(get_kb_item("MS/Lync/Ver"))
{
  ## Get Installed Path
  lyncPath = get_kb_item("MS/Lync/path");

  ## For MS Lync Basic
  if(!lyncPath){
    lyncPath = get_kb_item("MS/Lync/Basic/path");
  }

  if(lyncPath)
  {
    lyncPath1 = lyncPath + "OFFICE15";

   ## Get Version from 'Rtmpltfm.dll'
    commVer = fetch_file_version(sysPath:lyncPath1, file_name:"Rtmpltfm.dll");
    if(commVer)
    {
      if(commVer =~ "^(5)" && version_in_range(version:commVer, test_version:"5.0", test_version2:"5.0.8687.156"))
      {
        report = 'File checked:     ' + lyncPath1 + "\Rtmpltfm.dll" + '\n' +
                 'File version:     ' + commVer  + '\n' +
                 'Vulnerable range: ' + "5.0 - 5.0.8687.156" + '\n' ;
        security_message(data:report);
      }
    }
  }
}
exit(0);
