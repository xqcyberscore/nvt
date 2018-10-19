###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4032213.nasl 11972 2018-10-19 05:34:20Z cfischer $
#
# Microsoft Excel Viewer 2007 SP3 RCE and Information Disclosure Vulnerabilities (KB4032213)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813291");
  script_version("$Revision: 11972 $");
  script_cve_id("CVE-2018-8375", "CVE-2018-8382");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:34:20 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-15 11:29:13 +0530 (Wed, 15 Aug 2018)");
  script_name("Microsoft Excel Viewer 2007 SP3 RCE and Information Disclosure Vulnerabilities (KB4032213)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4032213");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaws exists when Microsoft Excel fails
  to properly handle objects in memory and improperly discloses the contents of
  its memory ");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run arbitrary code and use the information to compromise the
  computer or data.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Excel Viewer 2007 Service Pack 3");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4032213");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/XLView/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(!excelviewVer){
  exit(0);
}

if(excelviewVer =~ "^(12\.)" && version_is_less(version:excelviewVer, test_version:"12.0.6802.5000"))
{
  report = report_fixed_ver(file_checked:"Xlview.exe",
                            file_version:excelviewVer, vulnerable_range:"12.0 - 12.0.6802.4999");
  security_message(data:report);
  exit(0);
}
