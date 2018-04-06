###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mem_corr_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Opera Browser 'SELECT' HTML Tag Remote Memory Corruption Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to trigger an invalid
  memory write operation, and consequently cause a denial of service or possibly
  execute arbitrary code.
  Impact Level: Application";
tag_affected = "Opera Web Browser Version before 10.61 on windows.";
tag_insight = "The flaw is due to an error in 'VEGAOpBitmap::AddLine' function, which
  fails to properly initialize memory during processing of the SIZE attribute of
  a SELECT element.";
tag_solution = "Upgrade to Opera Web Browser Version 10.61 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to memory
  corruption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801788");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-1824");
  script_bugtraq_id(47764);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Opera Browser 'SELECT' HTML Tag Remote Memory Corruption Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67338");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517914/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get Opera Version from KB
operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  ## Grep for Opera Versions prior to 10.61
  if(version_is_less(version:operaVer, test_version:"10.61")){
    security_message(0);
  }
}
