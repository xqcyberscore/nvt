###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barcode_actvx_bof_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# BarCodeWiz 'BarcodeWiz.dll' ActiveX Control BOF Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to execute
arbitrary code within the context of the affected application that uses the
ActiveX control. Failed exploit attempts will result in a denial-of-service
condition.

Impact Level: Application";

tag_affected = "BarCodeWiz Barcode 3.29 and prior.";

tag_insight = "The flaw is due to a boundary error in 'BarcodeWiz.dll' when
handling arguments passed to the 'LoadProperties()' method, which allows remote
attackers to execute arbitrary code via a long argument to the LoadProperties
method.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host has BarCodeWiz installed and is prone to Remote
bufer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801395");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2010-2932");
  script_bugtraq_id(42097);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("BarCodeWiz 'BarcodeWiz.dll' ActiveX Control BOF Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40786");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14519");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14504");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14505");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_barcode_detect.nasl");
  script_mandatory_keys("BarCodeWiz/Barcode/AX");
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
include("secpod_activex.inc");
include("secpod_smb_func.inc");

## Get the barcode version from KB
bcVer = get_kb_item("BarCodeWiz/Barcode/AX");
if(!bcVer){
  exit(0);
}

if(version_is_less_equal(version:bcVer, test_version:"3.29"))
{
  ## Path for the BarcodeWiz.dll file
  path = registry_get_sz(key:"SOFTWARE\BarCodeWiz\AX\",
                        item:"ProgramDir");
  if(!path){
    exit(0);
  }

  path = path + "\DLL\BarcodeWiz.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

  ## Confirm the file existence
  dllSize = get_file_size(share:share, file:file);
  if(dllSize)
  {
    if(is_killbit_set(clsid:"{CD3B09F1-26FB-41CD-B3F2-E178DFD3BCC6}") == 0){
      security_message(0);
   }
  }
}
