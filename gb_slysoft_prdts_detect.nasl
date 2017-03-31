###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_slysoft_prdts_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# SlySoft Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_summary = "This script detects the installed version of SlySoft Product(s)
  and sets the result in KB.";

if(description)
{
  script_id(800391);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SlySoft Product(s) Version Detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800391";
SCRIPT_DESC = "SlySoft Product(s) Version Detection";

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

function slysoftGetVer(path)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path);

  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r){
    close(soc);
    exit(0);
  }

  prot = smb_neg_prot(soc:soc);
  if(!prot){
    close(soc);
    exit(0);
  }

  r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                        prot:prot);
  if(!r){
    close(soc);
    exit(0);
  }

  uid = session_extract_uid(reply:r);
  if(!uid){
    close(soc);
    exit(0);
  }

  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(!r){
    close(soc);
    exit(0);
  }

  tid = tconx_extract_tid(reply:r);
  if(!tid){
    close(soc);
    exit(0);
  }

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid){
    close(soc);
    exit(0);
  }

  slysoftVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod");
  if(!slysoftVer){
    slysoftVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:332560);
    close(soc);
    if(!slysoftVer){
      return NULL;
    }
  }
  close(soc);
  return slysoftVer;
}

if(!registry_key_exists(key:"SOFTWARE\SlySoft"))
{
  if(!registry_key_exists(key:"SOFTWARE\Elaborate Bytes")){
    exit(0);
  }
}

# Get the Version for AnyDVD
anydvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\AnyDVD.exe", item:"Path");
if(anydvdPath)
{
  anydvdVer = slysoftGetVer(path:anydvdPath + "\AnyDVD.exe");
  if(anydvdVer != NULL)
  {
    set_kb_item(name:"AnyDVD/Ver", value:anydvdVer);
    log_message(data:"AnyDVD version " + anydvdVer +
                       " running at location " + anydvdPath +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:anydvdVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:slysoft:anydvd:");

  }
}

# Get the Version for CloneDVD
clonedvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                   "\App Paths\CloneDVD2.exe", item:"Path");
if(clonedvdPath)
{
  dvdVer = slysoftGetVer(path:clonedvdPath + "\CloneDVD2.exe");
  if(dvdVer != NULL)
  {
    set_kb_item(name:"CloneDVD/Ver", value:dvdVer);
    log_message(data:"CloneDVD version " + dvdVer +
                       " running at location " + clonedvdPath +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:dvdVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:slysoft:clonedvd:");

  }
}
else
{
  clonedvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\App Paths\CloneDVD.exe", item:"Path");
  dvdVer = slysoftGetVer(path:clonedvdPath + "\CloneDVD.exe");
  if(dvdVer != NULL)
  {
    set_kb_item(name:"CloneDVD/Ver", value:dvdVer);
    log_message(data:"CloneDVD version " + dvdVer +
                       " running at location " + clonedvdPath +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:dvdVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:slysoft:clonedvd:");

  }
}

# Get the Version for CloneCD
clonecdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\App Paths\CloneCD.exe", item:"Path");
if(clonecdPath)
{
  cdVer = slysoftGetVer(path:clonecdPath + "\CloneCD.exe");
  if(cdVer != NULL)
  {
    set_kb_item(name:"CloneCD/Ver", value:cdVer);
    log_message(data:"CloneCD version " + cdVer + 
                       " running at location " + clonecdPath +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:cdVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:slysoft:clonecd:");

  }
}

# Get the Version for Virtual CloneDrive
drivePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\VCDPrefs.exe", item:"Path");
if(drivePath)
{
  driveVer = slysoftGetVer(path:drivePath + "\VCDPrefs.exe");
  if(driveVer != NULL)
  {
    set_kb_item(name:"VirtualCloneDrive/Ver", value:driveVer);
    log_message(data:"Virtual CloneDrive version " + driveVer +
                       " running at location " + drivePath +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:driveVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:slysoft:virtualclonedrive:");

  }
}
