###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mutt_detect.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Mutt Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-22
# Revised to comply with Change Request #57.
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

tag_summary = "Detection of installed version of Mutt.

The script logs in via ssh, searches for executable 'mutt' and
queries the found executables via command line option '-v'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900675";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Mutt Version Detection");
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

paths = find_bin(prog_name:"mutt", sock:sock);
foreach executableFile (paths)
{
  executableFile = chomp(executableFile);
  muttVer = get_bin_version(full_prog_name:executableFile, sock:sock,
            version_argv:"-v", ver_pattern:"Mutt (([0-9.]+)([a-z])?)");
  if(muttVer[1] != NULL)
  {
    set_kb_item(name:"Mutt/Ver", value:muttVer[1]);
   
    cpe = build_cpe(value:muttVer[1], exp:"^([0-9.]+)", base:"cpe:/a:mutt:mutt:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

    log_message(data:'Detected Mutt version: ' + muttVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + muttVer[max_index(muttVer)-1]);
  }
}

ssh_close_connection();
