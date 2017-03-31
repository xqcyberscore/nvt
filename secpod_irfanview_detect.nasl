###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_irfanview_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# IrfanView Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2012-02-14
#  - Added register_cpe, initialized variables
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

tag_summary = "This script detects the installed version of IrfanView and
  sets the reuslt in KB.";

if(description)
{
  script_id(900376);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IrfanView Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900376";
SCRIPT_DESC = "IrfanView Version Detection";

## Variable Initialisation
path = "";
irViewPath = "";
irViewVer = "";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase)
{
  local_var cpe;
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
  if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView";
if(!(registry_key_exists(key:key))){
  exit(0);
}

path = registry_get_sz(key:key, item:"UninstallString");
if(path != NULL)
{
  irViewPath = path - "\iv_uninstall.exe" + "\i_view32.exe";
  irViewVer = GetVersionFromFile(file:irViewPath, verstr:"prod");

  if(irViewVer == NULL){
    exit(0);
  }

  set_kb_item(name:"IrfanView/Ver", value:irViewVer);
  log_message(data:"IrfanView version " + irViewVer +
               " installed at location " + irViewPath + " was detected on " +
               "the host");

  ## build cpe and store it as host_detail
  register_cpe(tmpVers:irViewVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:irfanview:irfanview:");
}
