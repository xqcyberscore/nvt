##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_robo_ftp_client_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# Robo-FTP Client Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2010-11-04
#   - Modified to detect version from registry
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

tag_summary = "This script finds the installed Robo-FTP Client version and saves the
  result in KB item.";

if(description)
{
  script_id(801053);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Robo-FTP Client Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801053";
SCRIPT_DESC = "Robo-FTP Client Version Detection";

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Robo-FTP" >< name)
  {
    ftpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(ftpVer))
    {
      set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);
      log_message(data:"Robo-FTP Client version " + ftpVer +
                         " running at location " + path +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:ftpVer, tmpExpr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", tmpBase:"cpe:/a:robo-ftp:robo-ftp:");

      exit(0);
    }
  }
}

path = registry_get_sz(key:"SOFTWARE\Robo-FTP", item:"InstallDir");
if(path != NULL)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path +
                                                     "\Robo-FTP.exe");
  ftpVer = GetVer(share:share, file:file);
  if(!isnull(ftpVer))
  {
    set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);
    log_message(data:"Robo-FTP Client version " + ftpVer +
                       " running at location " + path +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:ftpVer, tmpExpr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", tmpBase:"cpe:/a:robo-ftp:robo-ftp:");

  }
}
