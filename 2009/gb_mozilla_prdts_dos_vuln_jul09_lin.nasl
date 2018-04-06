###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_dos_vuln_jul09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Products 'select()' Denial Of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_solution = "Upgrade to Firefox version 2.0.0.19 or 3.0.5 or later
  http://www.mozilla.com/en-US/firefox/all.html
  Upgrade to Seamonkey version 1.1.17 or later
  http://www.seamonkey-project.org/releases/
  Apply patch for Thunderbird through above mozilla engine update
  http://www.mozillamessaging.com/

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will let attackers to cause application crash by
  consuming the memory.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 1.1.17
  Thunderbird version 2.0.0.22 and prior
  Firefox version before 2.0.0.19 and 3.x before 3.0.5 on Linux.";
tag_insight = "A null pointer dereference error occurs while calling the 'select' method
  with a large integer, that results in continuous allocation of x+n bytes of
  memory, exhausting memory after a while.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800849");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2535", "CVE-2009-1692");
  script_bugtraq_id(35446);
  script_name("Mozilla Products 'select()' Denial Of Service Vulnerability (Linux)");

  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9160");
  script_xref(name : "URL" , value : "http://www.g-sec.lu/one-bug-to-rule-them-all.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Linux/Ver");
if(ffVer)
{
  # Grep for Firefox version < 2.0.0.19 and < 3.0.5
  if(version_is_less(version:ffVer, test_version:"2.0.0.19")||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.4"))
  {
    security_message(0);
    exit(0);
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version < 1.1.17
  if(version_is_less(version:smVer, test_version:"1.1.17"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version <= 2.0.0.22
  if(version_is_less_equal(version:tbVer, test_version:"2.0.0.22")){
    security_message(0);
  }
}
