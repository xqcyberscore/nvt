###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ghostscript_code_exec_vuln.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# Ghostscript Arbitrary Code Execution Vulnerability.
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation allows the attackers to execute arbitrary code or
  cause a denial of service.
  Impact Level: Application";
tag_affected = "Ghostscript versions prior to 8.71";
tag_insight = "The flaw is due to Off-by-one error in the TrueType bytecode
  interpreter in Ghostscript that allows remote attackers to execute arbitrary
  code or cause a denial of service (heap memory corruption) via a malformed
  TrueType font in a document.";
tag_solution = "Upgrade to Ghostscript version 8.71 or later,
  For updates refer to http://www.ghostscript.com/";
tag_summary = "This host is installed with Ghostscript and is prone to
  arbitrary code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801269");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2009-3743");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ghostscript Arbitrary Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/644319");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/JALR-87YGN8");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_require_keys("Ghostscript/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get the version from KB
ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

## Check for the Ghostscript versions prior to  8.71
if(version_is_less(version:ghostVer, test_version:"8.71")){
   security_message(0);
}
