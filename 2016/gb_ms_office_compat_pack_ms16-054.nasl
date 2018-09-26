###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_compat_pack_ms16-054.nasl 11614 2018-09-26 07:39:28Z asteins $
#
# Microsoft Office Compatibility Pack Remote Code Execution Vulnerability (3155544)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807327");
  script_version("$Revision: 11614 $");
  script_cve_id("CVE-2016-0198");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 09:39:28 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-05-11 15:37:44 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack Remote Code Execution Vulnerability (3155544)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-054");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws is due to an improper handling
  of files in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code and corrupt memory in the context of the
  current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link, https://technet.microsoft.com/en-us/security/bulletin/ms16-054");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/kb/3155544");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/kb/3115115");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-042");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/WordCnv/Version");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("SMB/Office/ComptPack/Version") =~ "^12\..*")
{
  wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
  if(wordcnvVer && wordcnvVer =~ "^12.*")
  {
    # Office Word Converter
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
    if(path)
    {
      sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office12", file_name:"Wordcnv.dll");
      if(sysVer)
      {
        if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6748.4999"))
        {
          report = 'File checked:      Wordcnv.dll' + '\n' +
                   'File version:      ' + sysVer  + '\n' +
                   'Vulnerable range:  12.0 - 12.0.6748.4999' + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
