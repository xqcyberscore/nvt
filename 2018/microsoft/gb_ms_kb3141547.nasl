###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb3141547.nasl 8378 2018-01-11 14:38:57Z gveerendra $
#
# Microsoft SharePoint Foundation 2010 Service Pack 2 Information Disclosure Vulnerability (KB3141547)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812726");
  script_version("$Revision: 8378 $");
  script_cve_id("CVE-2018-0790");
  script_bugtraq_id(102391);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 15:38:57 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 10:03:51 +0530 (Wed, 10 Jan 2018)");
  script_name("Microsoft SharePoint Foundation 2010 Service Pack 2 Information Disclosure Vulnerability (KB3141547)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3141547.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft SharePoint 
  Server does not properly sanitize a specially crafted web request to an 
  affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to perform cross-site scripting 
  attacks on affected systems and run script in the security context of the 
  current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft SharePoint Foundation 2010 Service Pack 2.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/3141547");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3141547");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

shareVer = "";
dllVer = "";
path = "";

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_server') ) exit( 0 );

shareVer = infos['version'];
if(!shareVer){
  exit(0);
}

if(shareVer =~ "^14\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\SERVER14\Server Setup Controller";

    dllVer = fetch_file_version(sysPath:path, file_name:"Wsssetup.dll");

    if(dllVer && version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7184.4999"))
    {
      report = report_fixed_ver(file_checked:path + "\Wsssetup.dll",
                                file_version:dllVer, vulnerable_range:"14.0 - 14.0.7184.4999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);
