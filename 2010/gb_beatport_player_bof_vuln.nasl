###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beatport_player_bof_vuln.nasl 8254 2017-12-28 07:29:05Z teissa $
#
# Beatport Player '.m3u' File Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to execute
arbitrary code on the system or cause the application to crash.

Impact Level: Application";

tag_affected = "Beatport Player version 1.0.0.283 and prior.";

tag_insight = "The flaw is due to improper bounds ckecking when opening
specially crafted '.M3U' file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one."; 

tag_summary = "This host is installed with Beatport Player and is prone to
buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800749");
  script_version("$Revision: 8254 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 08:29:05 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4756");
  script_bugtraq_id(34793);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Beatport Player '.m3u' File Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8592");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50267");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
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

if(!registry_key_exists(key:"SOFTWARE\Native Instruments\TraktorBeatport")){
  exit(0);
}

tbpName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Native Instruments Traktor Beatport Player",
                         item:"DisplayName");

if("Native Instruments Traktor Beatport Player" >< tbpName)
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        item:"CommonFilesDir");
  if(isnull(path)){
    exit(0);
  }

  path = path - "\Common Files" + "\Native Instruments\Traktor Beatport Player" +
                                 "\TraktorBeatport.exe";
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path);

  ver = GetVer(file:file, share:share);
  if(ver != NULL)
  {
    if(version_is_less_equal(version:ver, test_version:"1.0.0.283")){
     security_message(0);
    }
  }
}
