###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_pdf_mem_crptn_vuln.nasl 3565 2016-06-21 07:20:17Z benallard $
#
# Foxit Reader PDF File Handling Memory Corruption Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow the attackers to execute arbitrary code
  on the target system.
  Impact Level: System/Application";
tag_affected = "Foxit Reader version prior to 5.3 on Windows XP and Windows 7";
tag_insight = "An unspecified error when parsing PDF files and can be exploited to corrupt
  memory.";
tag_solution = "Upgrade to the Foxit Reader version 5.3 or later,
  For updates refer to http://www.foxitsoftware.com/Secure_PDF_Reader/";
tag_summary = "The host is installed with Foxit Reader and is prone to memory
  corruption vulnerability.";

if(description)
{
  script_id(802957);
  script_version("$Revision: 3565 $");
  script_cve_id("CVE-2012-4337");
  script_bugtraq_id(55150);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:20:17 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-09-07 11:03:23 +0530 (Fri, 07 Sep 2012)");
  script_name("Foxit Reader PDF File Handling Memory Corruption Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50359");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027424");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Foxit Reader");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_require_keys("Foxit/Reader/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

## Variable Initialization
foxitVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win7:2, win7x64:2) <= 0){
  exit(0);
}

## Get the version from KB
foxitVer = get_kb_item("Foxit/Reader/Ver");
if(!foxitVer){
  exit(0);
}

## Check for Foxit Reader Version less than 5.3 => 5.3.0.0423
if(version_is_less(version:foxitVer, test_version:"5.3.0.0423")){
  security_message(0);
}
