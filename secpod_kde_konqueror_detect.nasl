###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kde_konqueror_detect.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# KDE Konqueror Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-22
# Revised to comply with Change Request #57.
#
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

tag_summary = "Detection of installed version of KDE Konqueror.

The script logs in via ssh, searches for executable 'konqueror' and
queries the found executables via command line option '-v'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900902";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("KDE Konqueror Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

konqerName = find_file(file_name:"konqueror", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach executableFile (konqerName)
{
  executableFile = chomp(executableFile);
  konqerVer = get_bin_version(full_prog_name:executableFile, version_argv:"-v",
                 ver_pattern:"Konqueror: ([0-9.]+).?((rc|RC)?[0-9]+)?", sock:sock);

  if(konqerVer[1] != NULL)
  {
    if(konqerVer[2] != NULL){
       Ver = konqerVer[1] + "." + konqerVer[2];
     }
    else
      Ver = konqerVer[1];

    set_kb_item(name:"KDE/Konqueror/Ver", value:Ver);
      
    cpe = build_cpe(value:Ver, exp:"Konqueror: ([0-9.]+)", base:"cpe:/a:kde:konqueror:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

    log_message(data:'Detected KDE Konqueror version: ' + Ver +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + konqerVer[max_index(konqerVer)-1]);
  }
}

ssh_close_connection();
