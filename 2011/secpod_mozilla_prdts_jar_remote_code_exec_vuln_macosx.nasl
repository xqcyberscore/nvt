###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_jar_remote_code_exec_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Products jar Files Remote Code Execution Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_solution = "Upgrade to Mozilla Firefox version 3.6.25 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version to 3.1.17 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary code in
  the context of the user running an affected application.
  Impact Level: Application";
tag_affected = "Thunderbird version prior to 3.1.17
  Mozilla Firefox version prior to 3.6.25";
tag_insight = "The flaw is due to not considering '.jar' files to be executable files
  which allows remote attackers to bypass intended access restrictions via a
  crafted file.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird and is prone
  to remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902777");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3666");
  script_bugtraq_id(51139);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-22 13:17:34 +0530 (Thu, 22 Dec 2011)");
  script_name("Mozilla Products jar Files Remote Code Execution Vulnerability (MAC OS X)");

  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51139/discuss");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-59.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.6.25"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("ThunderBird/MacOSX/Version");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"3.1.17")){
    security_message(0);
  }
}
