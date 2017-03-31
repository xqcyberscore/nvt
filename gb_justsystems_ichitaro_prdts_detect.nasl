###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justsystems_ichitaro_prdts_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# JustSystems Ichitaro Product(s) Version Detection
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

tag_summary = "This script finds the installed product version of Ichitaro
  and Ichitaro viewer and sets the result in KB.";

if(description)
{
  script_id(800542);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("JustSystems Ichitaro Product(s) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800542";
SCRIPT_DESC = "JustSystems Ichitaro Product(s) Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Justsystem")){
  exit(0);
}

viewerPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\TAROVIEW.EXE", item:"Path");
if(viewerPath)
{
  path = viewerPath + "\TAROVIEW.EXE";
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path);
  viewerVer = GetVer(file:file, share:share);

  if(viewerVer != NULL)
  {
    set_kb_item(name:"Ichitaro/Viewer/Ver", value:viewerVer);
    log_message(data:"Ichitaro Viewer version " + viewerVer + " running at" + 
                       " location " + viewerPath + " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:viewerVer, tmpExpr:"^(19\..*)", tmpBase:"cpe:/a:justsystem:ichitaro_viewer:5.1");

  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("ATOK" >< appName)
  {
    appVer = eregmatch(pattern:"ATOK ([0-9.]+)", string:appName);
    if(appVer[1] != NULL)
    {
      set_kb_item(name:"Ichitaro/Ver", value:appVer[1]);
      log_message(data:"Ichitaro version " + appVer[1] +
                         " was detected on the host");
 
      ## build cpe and store it as host_detail
      register_cpe(tmpVers:appVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:ichitaro:ichitaro:");

    }
    exit(0);
  }
}
