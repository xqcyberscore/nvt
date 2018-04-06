##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flexcell_activex_file_overwrire_vuln_900406.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: FlexCell Grid Control ActiveX Arbitrary File Overwrite Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_affected = "FlexCell Grid Control ActiveX 5.7.1 and prior on all Windows Platform.

  Workaround:
  Set the killbit for the affected ActiveX control.
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes.
  Impact Level: System/Application";
tag_insight = "The vulnerability is due to an error in the 'httpDownloadFile' method
  in the 'FlexCell.ocx' component file.";
tag_summary = "This host is installed with FlexCell Grid Control ActiveX and is
  prone to arbitrary File Overwrite vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900406");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5404");
  script_bugtraq_id(32443);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("FlexCell Grid Control ActiveX Arbitrary File Overwrite Vulnerability");

  script_xref(name : "URL" , value : "http://www.grid2000.com");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32829");

  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

entries = registry_enum_keys(key:key);
foreach item (entries)
{
  flexcellName = registry_get_sz(key:key + item, item:"DisplayName");
  if("FlexCell Grid Control" >< flexcellName)
  {
    # Grep or versions 5.7.1 and prior.
    if(egrep(pattern:"^([0-4]\..*|5\.[0-6](\..*)?|5\.7(\.[01])?)$",
             string:registry_get_sz(key:key + item, item:"DisplayVersion"))){
      security_message(0);
    }
  }
}
