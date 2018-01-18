###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_oct10.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Mozilla Products Multiple Vulnerabilities october-10 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_solution = "Upgrade to Firefox version 3.6.11 or 3.5.14 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.9 or later
  http://www.seamonkey-project.org/releases/

  Upgrade to Thunderbird version 3.0.9 or 3.1.5 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to to cause a denial of service
  or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 2.0.9
  Firefox version prior to 3.5.14 and 3.6.x before 3.6.11
  Thunderbird version proior to 3.0.9 and 3.1.x before 3.1.5";
tag_insight = "The flaws are due to:
  - A wildcard IP address in the 'subject&qts' Common Name field of an X.509
    certificate.
  - not properly setting the minimum key length for 'Diffie-Hellman Ephemeral'
   (DHE) mode, which makes it easier for remote attackers to defeat
    cryptographic protection mechanisms via a brute-force attack.
  - Passing an excessively long string to 'document.write' could cause text
    rendering routines to end up in an inconsistent state with sections of
    stack memory being overwritten with the string data.
  - not properly handling certain modal calls made by 'javascript: URLs' in
    circumstances related to opening a new window and performing cross-domain
    navigation.
  - an untrusted search path vulnerability.
  - Use-after-free vulnerability in the nsBarProp function.
  - error in 'LookupGetterOrSetter' function, which does not properly support
    'window.__lookupGetter__ function' calls that lack arguments.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801467");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3179", "CVE-2010-3178",
                "CVE-2010-3181", "CVE-2010-3180", "CVE-2010-3183");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities October-10 (Windows)");

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-70.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-72.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-65.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-69.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.5.14") ||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.10"))
    {
      security_message(0);
      exit(0);
    }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version
  if(version_is_less(version:smVer, test_version:"2.0.9"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"3.0.9") ||
    version_in_range(version:tbVer, test_version:"3.1.0", test_version2:"3.1.4")){
    security_message(0);
  }
}
