###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_dos_vuln_jun09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Thunderbird/Seamonkey DoS Vulnerability June-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code via
  e-mail messages, and result in Denial of Service condition.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 1.1.17 and
  Thunderbird version prior to 2.0.0.22 on Linux.";
tag_insight = "The flaw exists when application fails to handle user input messages via
  a multipart or alternative e-mail message containing a text or enhanced part
  that triggers access to an incorrect object type.";
tag_solution = "Upgrade to Seamonkey version 1.1.17
  http://www.seamonkey-project.org/releases
  Upgrade to Thunderbird version 2.0.0.22
  http://www.mozillamessaging.com/en-US/thunderbird/all.html";
tag_summary = "The host is installed with Thunderbird/Seamonkey and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900390");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2210");
  script_bugtraq_id(35461);
  script_name("Mozilla Thunderbird/Seamonkey DoS Vulnerability June-09 (Linux)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51315");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version prior to 1.1.17
  if(version_is_less(version:smVer, test_version:"1.1.17")){
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version prior to 2.0.0.22
  if(version_is_less(version:tbVer, test_version:"2.0.0.22")){
    security_message(0);
  }
}
