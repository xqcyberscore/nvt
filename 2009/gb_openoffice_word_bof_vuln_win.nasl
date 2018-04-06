###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_word_bof_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenOffice.org Documents Parsing Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful remote exploitation could result in arbitrary code execution on
  the affected system which leads to application crash and compromise a
  vulnerable system.
  Impact Level: System/Application";
tag_affected = "OpenOffice Version prior to 3.1.1 on Windows.";
tag_insight = "- An integer underflow error occurs when parsing certain records in a
    Word document table.
  - An heap overflow error occurs when parsing certain records in a Word
    document when opening a malicious Word document.";
tag_solution = "Upgrade to OpenOffice Version 3.1.1 or later
  For updates refer to http://www.openoffice.org/";
tag_summary = "The host has OpenOffice installed and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800696");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_bugtraq_id(36200);
  script_name("OpenOffice.org Word Documents Parsing Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-27/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2490");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
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

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer)
{
  exit(0);
}

# Check for OpenOffice version prior to 3.1.1 (3.1.9420)
if(version_is_less(version:openVer, test_version:"3.1.9420")){
  security_message(0);
}
