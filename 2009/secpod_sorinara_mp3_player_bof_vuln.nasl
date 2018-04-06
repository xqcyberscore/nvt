###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sorinara_mp3_player_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sorinara Soritong MP3 Player Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker craft a malicious
m3u playlist file and trick the user to open the application which will cause
stack overflow in the affected system and will crash the application.";

tag_affected = "Soritong MP3 Player version 1.0 and prior";

tag_insight = "This flaw is due to an improper boundary checking when
processing '.m3u' files.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Sorinara Soritong MP3 Player and is prone
to Stack Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900650");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1643");
  script_bugtraq_id(34863);
  script_name("Sorinara Soritong MP3 Player Stack Overflow Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139,445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8624");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50398");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SoriTong\";
appName = registry_get_sz(key:key, item:"DisplayName");
if("SoriTong" >< appName)
{
  readmePath = registry_get_sz(key:key, item:"UninstallString");
  if(!readmePath){
    exit(0);
  }

  readmePath = readmePath - "\uninstall.exe /uninstall";
  readmePath = readmePath + "\Help";

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:readmePath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:readmePath + "\whatsnew.html");

  readmeText = read_file(share:share, file:file, offset:0, count:500);
  if(!readmeText){
    exit(0);
  }

  saritongVer = eregmatch(pattern:"Version ([0-9.]+)", string:readmeText);
  if(saritongVer[1] != NULL)
  {
    if(version_is_less_equal(version:saritongVer[1], test_version:"1.0")){
      security_message(0);
    }
  }
}
