###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_versalsoft_http_image_upldr_actvx_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Versalsoft HTTP Image Uploader ActiveX Vulnerability
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

tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.

  A workaround is to set the killbit for the CLSID {04FD48E6-0712-4937-B09E-F3D285B11D82}
  http://support.microsoft.com/kb/240797";

tag_impact = "Attacker may exploit this issue by deleting any arbitrary files on the
  remote system by tricking the user to visit a crafted malicious webpage.
  Impact Level: System/Application";
tag_affected = "Versalsoft HTTP Image Uploader 'UUploaderSvrD.dll' version 6.0.0.35 and
  prior.";
tag_insight = "Application has an insecure method 'RemoveFileOrDir()' declared in
  'UUploaderSvrD.dll' which allows the attacker to access, delete and
  corrupt system related files and folder contents.";
tag_summary = "This host is installed with Versalsoft HTTP Image Uploader
  and is prone to ActiveX vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800552");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2008-6638");
  script_bugtraq_id(28301);
  script_name("Versalsoft HTTP Image Uploader ActiveX Vulnerability");

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/5569");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41258");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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

imgupPath = registry_get_sz(key:"SOFTWARE\Universal\UImageUpoaderD",
                            item:"InstallPath");
if(!imgupPath){
  exit(0);
}

imgupPath = imgupPath + "\UUploaderSvrD.dll";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:imgupPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:imgupPath);

imgupVer = GetVer(share:share, file:file);
if(imgupVer != NULL &&
   version_is_less_equal(version:imgupVer, test_version:"6.0.0.35"))
{
  # Workaround check here
  if(is_killbit_set(clsid:"{04FD48E6-0712-4937-B09E-F3D285B11D82}") == 0){
    security_message(0);
  }
}
