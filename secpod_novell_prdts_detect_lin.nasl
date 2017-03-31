##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_prdts_detect_lin.nasl 2833 2016-03-11 08:36:30Z benallard $
#
# Novell Products Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated :
# Novell iPrint Client Detection
# Sujit Ghosal <sghosal@secpod.com>  on 2009-12-18 #6124
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script retrieves the installed version of Novell
  products and saves the result in KB.";

if(description)
{
  script_id(900598);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2833 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 09:36:30 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Novell Products Version Detection (Linux)");
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_summary("Set Version of Novell Products in KB");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900598";
SCRIPT_DESC = "Novell Products Version Detection (Linux)";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

#Set Version KB for Novell eDir Client
eDirPath = find_bin(prog_name:"ndsd", sock:sock);
foreach eDirFile (eDirPath)
{
  eDirVer = get_bin_version(full_prog_name:chomp(eDirFile), version_argv:"--version",
                   ver_pattern:"Novell eDirectory ([0-9.]+).?(SP[0-9]+)?", sock:sock);


  if(!isnull(eDirVer[1])) {
  
    if(eDirVer[2] != NULL){
        eDirVer = eDirVer[1] + "." + eDirVer[2];
    }
    else
      eDirVer = eDirVer[1];

    set_kb_item(name:"Novell/eDir/Lin/Ver", value:eDirVer);
    log_message(data:"Novell eDirectory version " + eDirVer + 
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:eDirVer, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:novell:edirectory:");


  }  
}

#Set Version KB for Novell iPrint Client
iPrintPaths = find_file(file_name:"iprntcmd", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach iPrintBin (iPrintPaths)
{
  iPrintVer = get_bin_version(full_prog_name:chomp(iPrintBin), sock:sock,
                              version_argv:"-v", ver_pattern:" v([0-9.]+)");
  if(iPrintVer[1] != NULL) {
    set_kb_item(name:"Novell/iPrint/Client/Linux/Ver", value:iPrintVer[1]);
    log_message(data:"Novell iPrint Client version " + iPrintVer[1] + 
                       " running at location " + iPrintBin +  
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:iPrintVer[1], tmpExpr:"^([0-9]\.[0-9]+)", tmpBase:"cpe:/a:novell:iprint_client:");

  }
}
ssh_close_connection();

