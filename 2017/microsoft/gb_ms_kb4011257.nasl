###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4011257.nasl 7992 2017-12-05 08:34:22Z teissa $
#
# Microsoft Project Server 2013 Elevation of Privilege Vulnerability (KB4011257)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:project_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812205");
  script_version("$Revision: 7992 $");
  script_cve_id("CVE-2017-11876");
  script_bugtraq_id(101754);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 09:34:22 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-15 09:49:22 +0530 (Wed, 15 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Project Server 2013 Elevation of Privilege Vulnerability (KB4011257)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011257");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exist due to microsoft project 
  server does not properly manage user sessions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to read content, use the victim's identity to take actions on the
  web application on behalf of the victim, such as change permissions and
  delete content, and inject malicious content in the browser of the victim.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Project Server 2013 Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the link, https://support.microsoft.com/en-us/help/4011257");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4011257");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_project_server_detect.nasl");
  script_require_keys("MS/ProjectServer/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

psVer = "";
dllVer = "";
path = "";

psVer = get_app_version(cpe:CPE);
if(!psVer){
  exit(0);
}

if(psVer =~ "^15\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\15\CONFIG\BIN";

    dllVer = fetch_file_version(sysPath:path,
             file_name:"microsoft.office.project.server.pwa.applicationpages.dll");

    if(dllVer && dllVer =~ "^15\.")
    {
      if(version_is_less(version:dllVer, test_version:"15.0.4981.1000"))
      {
        report = report_fixed_ver( file_checked:path + "\Microsoft.office.project.server.pwa.applicationpages.dll",
                                   file_version:dllVer, vulnerable_range:"15.0 - 15.0.4981.999" );
        security_message(data:report);
        exit(0);
      }
    }
  }
}
