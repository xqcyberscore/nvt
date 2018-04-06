###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Adobe Shockwave Player ActiveX Control BOF Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated the Fix.
# - Nikita MR <rnikita@secpod.com> 2009-11-06
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

tag_impact = "Successful attack could allow attackers to execute arbitrary code and to
  cause denial of service.
  Impact Level: Application";
tag_affected = "Adobe Shockwave Player 11.5.1.601 and prior on Windows.";
tag_insight = "An error occurs in the ActiveX Control (SwDir.dll) while processing malicious
  user supplied data containig a long PlayerVersion property value.";
tag_solution = "Upgrade to Adobe Shockwave Player 11.5.2.602
  http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host has Adobe Shockwave Player ActiveX Control installed
  and is prone to Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900949");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3244");
  script_bugtraq_id(36434, 36905);
  script_name("Adobe Shockwave Player ActiveX Control BOF Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9682");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

# Grep for version 11.5.1.601 and prior.
if(version_is_less_equal(version:shockVer, test_version:"11.5.1.601"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                           item:"Install Path");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                               "\Adobe\Director\SwDir.dll");

  dllOpn = open_file(share:share, file:file);
  if(isnull(dllOpn))
  {
    file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                                              "\Macromed\Director\SwDir.dll");
    dllOpn = open_file(share:share, file:file);
  }

  if(dllOpn &&
     is_killbit_set(clsid:"{233C1507-6A77-46A4-9443-F871F945D258}") == 0){
    security_message(0);
  }
}
