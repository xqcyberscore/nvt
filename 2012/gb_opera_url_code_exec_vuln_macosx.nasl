###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_url_code_exec_vuln_macosx.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Opera URL Processing Arbitrary Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Opera version prior to 11.64 on Mac OS X";
tag_insight = "The flaw is due to improper allocation of memory for URL strings,
  which allows remote attackers to execute arbitrary code or cause a denial
  of service (memory corruption and application crash) via a crafted string.";
tag_solution = "Upgrade to Opera version 11.64 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to code execution
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802653");
  script_version("$Revision: 8649 $");
  script_cve_id("CVE-2012-3561");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 17:17:17 +0530 (Thu, 21 Jun 2012)");
  script_name("Opera URL Processing Arbitrary Code Execution Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027066");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1016/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/mac/1164/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

## Check for opera version is less than 11.64
if(version_is_less(version:operaVer, test_version:"11.64")){
  security_message(0);
}
