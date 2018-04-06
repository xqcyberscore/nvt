###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synactis_allinthebox_activex_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Synactis All-In-The-Box ActiveX Remote Code Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_affected = "Synactis, All-In-The-Box ActiveX version 3.1.2.0 and prior.

  Workaround:
  Set the Killbit for the vulnerable CLSID {B5576893-F948-4E0F-9BE1-A37CB56D66FF}
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker overwrite arbitrary files on
  the system via a filename terminated by a NULL byte.
  Impact Level: System/Application";
tag_insight = "This flaw is due to an ActiveX control All_In_The_Box.ocx providing insecure
  SaveDoc method.";
tag_solution = "Upgrade to Synactis, All-In-The-Box ActiveX version 4.02 or later
  For updates refer to http://synactis.com/pdf-in-the-box-downloads.asp";
tag_summary = "This host is installed with All-In-The-Box ActiveX and is prone to
  Remote Code Execution Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800245");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0465");
  script_bugtraq_id(33535);
  script_name("Synactis All-In-The-Box ActiveX Remote Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33728");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7928");
  script_xref(name : "URL" , value : "http://www.dsecrg.com/pages/vul/show.php?id=62");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

ocxPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Synactis_All_In-The-Box_ActiveX",
                          item:"Unregister");
if(!ocxPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ocxPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ocxPath);

ocxVer = GetVer(file:file, share:share);
if(!ocxVer){
  exit(0);
}

# Grep for All_In_The_Box.ocx version 3.1.2.0 and prior
if(version_is_less_equal(version:ocxVer, test_version:"3.1.2.0"))
{
  if(is_killbit_set(clsid:"{B5576893-F948-4E0F-9BE1-A37CB56D66FF}") == 0){
    security_message(0);
  }
}
