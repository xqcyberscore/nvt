###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irfanview_jpeg2000_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IrfanView JPEG-2000 Plugin Remote Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: Application";
tag_affected = "IrfanView JPEG-2000 Plugin version prior to 4.33";
tag_insight = "The flaw is due to an error in the JPEG2000 plug-in when processing
  the Quantization Default (QCD) marker segment. This can be exploited to cause
  a stack-based buffer overflow via a specially crafted JPEG2000 (JP2) file.";
tag_solution = "Upgrade IrfanView JPEG-2000 Plugin version to 4.33 or later
  For updates refer to http://www.irfanview.com/plugins.htm";
tag_summary = "This host has IrfanView with JPEG-2000 plugin installed and is
  prone to stack based buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802576");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0897");
  script_bugtraq_id(51426);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 11:28:20 +0530 (Wed, 01 Feb 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("IrfanView JPEG-2000 Plugin Remote Stack Based Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47360");
  script_xref(name : "URL" , value : "http://www.irfanview.com/plugins.htm");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72398");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_require_keys("IrfanView/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable initialization
path = "";
plgVer = "";
irViewVer = NULL;

irViewVer = get_kb_item("IrfanView/Ver");
if(isnull(irViewVer)){
  exit(0);
}

# Get IrfanView JPEG-2000 Plugin installed path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView",
                       item:"UninstallString");
if(path != NULL)
{
  irViewPath = path - "\iv_uninstall.exe" + "\Plugins\JPEG2000.dll";
  plgVer = GetVersionFromFile(file:irViewPath, verstr:"prod");
  if(!plgVer){
    exit(0);
  }

  ## Check IrfanView JPEG-2000 Plugin version < 4.33
  if(version_is_less(version:plgVer, test_version:"4.33")){
    security_message(0);
  }
}
