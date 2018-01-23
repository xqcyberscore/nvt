###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_skype_insecure_lib_load_vuln_win.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Skype Insecure Library Loading Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow the attackers to execute
arbitrary code and conduct DLL hijacking attacks.

Impact Level: Application";

tag_affected = "Skype version 4.2.0.169 (4.2.169) and prior on Windows.";

tag_insight = "The flaw is due to improper validation of search path, which
allows remote attackers to execute arbitrary code and conduct DLL hijacking
attacks via a Trojan horse wab32.dll that is located in the same folder as
a .skype file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Skype and is prone to insecure library
loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902238");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3136");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Skype Insecure Library Loading Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/397165.php");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14766/");

  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_mandatory_keys("Skype/Win/Ver");
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

skypeVer = get_kb_item("Skype/Win/Ver");
if(!skypeVer){
  exit(0);
}

# Checkf for Skype version less than 4.2.0.169 (4.2.169)
if(version_is_less_equal(version:skypeVer, test_version:"4.2.169")){
  security_message(0);
}
