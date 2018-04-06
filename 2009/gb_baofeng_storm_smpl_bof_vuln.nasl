###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_baofeng_storm_smpl_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# BaoFeng Storm '.smpl' File Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Attacker may exploit this issue to execute arbitrary script code and may cause
  denial of service.
  Impact Level: Application";
tag_affected = "BaoFeng Storm version 3.09.62 and prior on Windows.";
tag_insight = "A boundary error occurs in the MediaLib.dll file while processing '.smpl'
  playlist file containing long pathname in the source attribute of ani item
  element.";
tag_solution = "Upgrade to the latest BaoFeng Storm version 3.09.07.08
  http://www.baofeng.com/";
tag_summary = "This host is installed with BaoFeng Storm and is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800914");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2617");
  script_bugtraq_id(35512);
  script_name("BaoFeng Storm '.smpl' File Buffer Overflow Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_baofeng_storm_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35592");
  script_xref(name : "URL" , value : "http://marc.info/?l=full-disclosure&m=124627617220913&w=2");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-06/0287.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

stormVer = get_kb_item("BaoFeng/Storm/Ver");
if(!stormVer){
  exit(0);
}

stormPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\Storm2", item:"DisplayIcon");
if(!stormPath){
  exit(0);
}

stormPath = stormPath - "Storm.exe" + "MediaLib.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:stormPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:stormPath);
stormdllVer = GetVer(share:share, file:file);

# If MediaLib.dll exists, check for the version of Storm.
if(stormdllVer != NULL)
{
  if(version_is_less_equal(version:stormVer, test_version:"3.09.62")){
    security_message(0);
  }
}
