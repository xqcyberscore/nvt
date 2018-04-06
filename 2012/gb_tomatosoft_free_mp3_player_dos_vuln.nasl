###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomatosoft_free_mp3_player_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# TomatoSoft Free Mp3 Player '.mp3' File Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to cause the
application to crash.

Impact Level: Application";

tag_affected = "TomatoSoft Free Mp3 Player 1.0";

tag_insight = "The flaw is due to an error when parsing a crafted '.mp3' file
containing an overly long argument.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with TomatoSoft Free Mp3 Player and is
prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802370");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-5043");
  script_bugtraq_id(51123);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-05 12:20:03 +0530 (Thu, 05 Jan 2012)");
  script_name("TomatoSoft Free Mp3 Player '.mp3' File Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71870");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18254/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Related Registry key
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mp3Player";
if(!registry_key_exists(key:key)){
  exit(0);
}

playerName = registry_get_sz(key:key , item:"Publisher");

## Confirm application
if("Tomatosoft" >< playerName)
{
  playerVer = registry_get_sz(key:key , item:"DisplayName");
  playerVer = eregmatch(pattern:"Mp3 Player ([0-9.]+)", string:playerVer);

  if(playerVer != NULL)
  {
    ## Check for TomatoSoft Free Mp3 Player < 1.0 version
    if(version_is_less_equal(version:playerVer[1], test_version:"1.0"))
    {
      security_message(0);
      exit(0);
    }
  }
}
