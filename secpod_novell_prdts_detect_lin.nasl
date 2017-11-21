##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_prdts_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900598");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Novell Products Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : "This script retrieves the installed
  version of Novell products and saves the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

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

    ## build cpe and store it as host_detail
    register_and_report_cpe(app:"Novell eDirectory version", ver:eDirVer, base:"cpe:/a:novell:edirectory:",
                            expr:"^([0-9.]+([a-z0-9]+)?)", insloc:eDirFile);
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

    ## build cpe and store it as host_detail
    register_and_report_cpe(app:"Novell iPrint Client", ver:iPrintVer[1], base:"cpe:/a:novell:iprint_client:",
                            expr:"^([0-9]\.[0-9]+)", insloc:iPrintBin);
  }
}
ssh_close_connection();
exit(0);
