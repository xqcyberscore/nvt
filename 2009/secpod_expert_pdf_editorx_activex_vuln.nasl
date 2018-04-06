###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_expert_pdf_editorx_activex_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Expert PDF EditorX ActiveX File Overwrite Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_affected = "Expert PDF EditorX 'VSPDFEditorX.ocx' version 1.0.1910.0 and prior.";

tag_impact = "Successful exploitation will let the attacker corrupt or overwrite
  arbitrary files on the user's system.
  Impact Level: System/Application";
tag_insight = "This flaw is due to an ActiveX control in Expert PDF EditorX file
  'VSPDFEditorX.ocx' providing insecure 'extractPagesToFile' method.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.

  A workaround is to set the Killbit for the vulnerable CLSID {89F968A1-DBAC-4807-9B3C-405A55E4A279}
  http://support.microsoft.com/kb/240797";
tag_summary = "This host is installed with Expert PDF EditorX and is
  prone to ActiveX file overwrite vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900481");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2008-6496");
  script_bugtraq_id(32664);
  script_name("Expert PDF EditorX ActiveX File Overwrite Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32990");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7358");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47166");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  editorx = registry_get_sz(key:key + item, item:"DisplayName");
  if("eXPert PDF EditorX" >< editorx)
  {
    ocxVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    break;
  }
}

if(ocxVer != NULL)
{
  # Grep for VSPDFEditorX.ocx version 1.0.1910.0 and prior
  if(version_is_less_equal(version:ocxVer, test_version:"1.0.1910.0"))
  {
    if(is_killbit_set(clsid:"{89F968A1-DBAC-4807-9B3C-405A55E4A279}") == 0){
      security_message(0);
    }
  }
}
