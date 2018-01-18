###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ghostscript_parser_bof_vuln_win.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Ghostscript Parser Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-05-20
#  -Included the CVE and related description
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows the attacker to execute arbitrary
code in the context of the affected application and can cause denial of service.

Impact Level: System/Application";

tag_affected = "Ghostscript version 8.70 and 8.64 on Windows.";

tag_insight = "These flaws are due to,
- Boundary error in the 'parser()' which allows the attackers to
execute arbitrary code via a crafted PostScript file.
- Buffer overflow and memory corruption errors when processing a recursive
procedure invocations, which could be exploited to crash an affected
application or execute arbitrary code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Ghostscript and is prone to
Buffer Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801336");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1869", "CVE-2010-1628");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ghostscript Parser Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/393809.php");
  script_xref(name : "URL" , value : "http://www.checkpoint.com/defense/advisories/public/2010/cpai-10-May.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_require_keys("Ghostscript/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

if(version_is_equal(version:ghostVer, test_version:"8.70") ||
   version_is_equal(version:ghostVer, test_version:"8.64")){
   security_message(0);
}
