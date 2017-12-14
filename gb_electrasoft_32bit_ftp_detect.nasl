###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_electrasoft_32bit_ftp_detect.nasl 8087 2017-12-12 13:12:04Z teissa $
#
# ElectraSoft 32bit FTP Version Detection
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

tag_summary = "This script detects the version of ElectraSoft 32bit FTP and sets
  the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800568");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8087 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ElectraSoft 32bit FTP Version Detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800568";
SCRIPT_DESC = "ElectraSoft 32bit FTP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\32bit FTP";
vendName = registry_get_sz(key:key, item:"Publisher");
if("ElectraSoft" >< vendName)
{
  readmePath = registry_get_sz(key:key, item:"InstallLoaction");
  if(!readmePath){
    exit(0);
  }
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:readmePath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:readmePath + "\README.TXT");
  readmeText = read_file(share:share, file:file, offset:0, count:100);
  if(!readmeText){
    exit(0);
  }
  ftpVer = eregmatch(pattern:"32bit FTP ([0-9.]+)", string:readmeText);
  if(ftpVer[1])
  {
    set_kb_item(name:"ElectraSoft/FTP/Ver", value:ftpVer[1]);
    log_message(data:"ElectraSoft FTP version " +ftpVer[1] + " running at" + 
                       " location " + readmePath + " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ftpVer[1], exp:"^([0-9.]+)", base:"cpe:/a:electrasoft:32bit_ftp:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
