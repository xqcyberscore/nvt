###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_win_xp_spi_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Windows XP 'SPI_GETDESKWALLPAPER' DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
#
# Updated to MS09-025 Bulletin
#   - By Sharath S <sharaths@secpod.com> On 2009-08-13
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

tag_impact = "Successful exploitation will let the attacker execute the malicious code
  into the context of an affected operating system and cause crash in the
  operating system.
  Impact Level: System";
tag_affected = "Microsoft Windows XP SP3 and prior.";
tag_insight = "Error exists while making an 'SPI_SETDESKWALLPAPER' SystemParametersInfo
  call with an improperly terminated 'pvParam' argument, followed by an
  'SPI_GETDESKWALLPAPER' SystemParametersInfo system calls.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-025.mspx";
tag_summary = "This host is running Windows XP operating system and is prone to
  Denial of Service vulnerability.

  This NVT has been superseded by KB968537 Which is addressed in NVT
  secpod_ms09-025.nasl (OID:1.3.6.1.4.1.25623.1.0.900669).";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900724");
  script_version("$Revision: 9350 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1808");
  script_bugtraq_id(35120);
  script_name("Windows XP 'SPI_GETDESKWALLPAPER' DoS Vulnerability");
  script_xref(name : "URL" , value : "http://www.ragestorm.net/blogs/?p=78");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as it is superseded by KB968537
          ## Which is addressed in secpod_ms09-025.nasl

include("secpod_reg.inc");

# Check Hotfix Missing  (MS09-025)
if(hotfix_missing(name:"968537") == 0){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0){
  security_message(0);
}
