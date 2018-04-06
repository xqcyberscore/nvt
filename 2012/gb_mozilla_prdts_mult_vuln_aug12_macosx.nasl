###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_aug12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities - August12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_solution = "Upgrade to Mozilla Firefox version 15.0 or ESR version 10.0.7 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.12 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 15.0 or ESR 10.0.7 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version before 2.12 on Mac OS X
  Thunderbird version before 15.0 on Mac OS X
  Mozilla Firefox version before 15.0 on Mac OS X
  Thunderbird ESR version 10.x before 10.0.7 on Mac OS X
  Mozilla Firefox ESR version 10.x before 10.0.7 on Mac OS X";
tag_insight = "- Use-after-free error exists within the functions
   'nsRangeUpdater::SelAdjDeleteNode', 'nsHTMLEditRules::DeleteNonTableElements',
   'MediaStreamGraphThreadRunnable::Run', 'nsTArray_base::Length',
   'nsHTMLSelectElement::SubmitNamesValues', 'PresShell::CompleteMove',
   'gfxTextRun::GetUserData' and 'gfxTextRun::CanBreakLineBefore'.
  - Multiple unspecified errors within funcions 'nsBlockFrame::MarkLineDirty'
    and the browser engine can be exploited to
    corrupt memory.
  - Errors in 'Silf::readClassMap' and 'Pass::readPass' functions within
    Graphite 2 library.
  - Use-after-free error exists within the WebGL implementation.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803012");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-3959", "CVE-2012-3958", "CVE-2012-3957", "CVE-2012-3972",
                "CVE-2012-3956", "CVE-2012-3971", "CVE-2012-1976", "CVE-2012-3970",
                "CVE-2012-1975", "CVE-2012-3969", "CVE-2012-1974", "CVE-2012-3968",
                "CVE-2012-1973", "CVE-2012-3967", "CVE-2012-3966", "CVE-2012-1970",
                "CVE-2012-3964", "CVE-2012-3963", "CVE-2012-3962", "CVE-2012-3978");
  script_bugtraq_id(55249);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 12:20:04 +0530 (Thu, 30 Aug 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities - August12 (Mac OS X)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/50088");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027450");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027451");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-57.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-58.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-62.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-63.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-64.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-70.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
ffVer = "";
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"10.0.7")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"14.0"))
  {
    security_message(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = "";
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.12"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"10.0.7")||
     version_in_range(version:tbVer, test_version:"11.0", test_version2:"14.0"))
  {
    security_message(0);
    exit(0);
  }
}
