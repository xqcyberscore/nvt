###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_free_download_mang_mult_bof_vuln_may10.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# Free Download Manager Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  in the context of the application or to compromise the application and the
  underlying computer.
  Impact Level: Application";
tag_affected = "Free Download Manager version prior to 3.0 build 852 on Windows.";
tag_insight = "Multiple buffer overflow errors exists due to boundary errors when,
  - opening folders within the 'Site Explorer'
  - opening websites in the 'Site Explorer' functionality
  - setting the directory on 'FTP' servers
  - handling redirects and
  - Sanitising the 'name' attribute of the 'file' element of
    metalink files before using it to download files.";
tag_solution = "Upgrade to version 3.0 bulid 852
  http://www.freedownloadmanager.org/download.htm";
tag_summary = "This host has Free Download Manager installed and is prone to
  multiple buffer overflow vulnerabilities.";

if(description)
{
  script_id(801339);
  script_version("$Revision: 7585 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-0998", "CVE-2010-0999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Free Download Manager Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39447");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-68/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511282/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_free_download_mang_detect.nasl");
  script_require_keys("FreeDownloadManager/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

fdmVer = get_kb_item("FreeDownloadManager/Ver");
if(!fdmVer){
  exit(0);
}

# Grep for Chrome version prior to 3.0 build 852
if(version_is_less(version:fdmVer, test_version:"3.0.852.0")){
  security_message(0);
}
