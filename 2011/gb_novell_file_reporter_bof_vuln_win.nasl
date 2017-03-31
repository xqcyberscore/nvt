###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_bof_vuln_win.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.
  Impact Level: Application/System";
tag_affected = "Novell File Reporter (NFR) before 1.0.2";
tag_insight = "The flaw exists within 'NFRAgent.exe' module, which allows remote attackers
  to execute arbitrary code via unspecified XML data to port 3037.";
tag_solution = "Upgrade Novell File Reporter 1.0.2 or later,
  For updates refer to http://download.novell.com/Download?buildid=rCAgCcbPH9s~";
tag_summary = "This host is installed with Novell File Reporter and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801918);
  script_version("$Revision: 3117 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0994");
  script_bugtraq_id(47144);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-116/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517321/100/0/threaded");

  script_summary("Check for the version of Novell File Reporter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/FileReporter/Ver");
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

## Get version from KB
nfrVer = get_kb_item("Novell/FileReporter/Ver");
if(nfrVer)
{
  ## Check for  Novell File Reporter version less than 1.0.2
  ## Novell File Reporter(1.0.1) 1.0.117
  if(version_is_less_equal(version:nfrVer, test_version:"1.0.117")){
    security_message(0);
  }
}
