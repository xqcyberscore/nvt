##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_virtualbox_detect_lin.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Oracle VirtualBox Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by: <santu@secpod.com> on 2011-01-28
# Updated to detect the recent versions also
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-21
# Revsied to comply with Change Request #57.
#
# Updated by: Shakeel <bshakeel@secpod.com> on 2013-10-28
# According to new style script_tags
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
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.901051";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Oracle VirtualBox Version Detection (Linux)");

  tag_summary =

  "Detection of installed versions of Sun/Oracle VirtualBox,
a hypervisor tool, on Linux systems.

The script logs in via ssh, searches for executables of VirtualBox and
queries the found executables via command line option '--version'.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

function register_cpe(tmpVers, tmpExpr, tmpBase, binFile){
  local_var cpe;
  cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
  if(cpe)
    register_product(cpe:cpe, location:binFile, nvt:SCRIPT_OID);
  ## Build Report
    log_message(data: build_detection_report(app: "Oracle/Sun Virtual Box",
                                             version: tmpVers,
                                             install: binFile,
                                             cpe: cpe,
                                             concluded: tmpVers));
    exit(0);


}

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

getPath = find_bin(prog_name:"VBoxManage", sock:sock);
foreach executableFile (getPath)
{
  vbVer = get_bin_version(full_prog_name:chomp(executableFile), sock:sock,
                          version_argv:"--version",
                          ver_pattern:"([0-9.]+([a-z0-9]+)?)");
  if(vbVer[1] != NULL)
  {
    Ver = ereg_replace(pattern:"([a-z])", string:vbVer[1], replace:".");
    if(Ver){
      set_kb_item(name:"Sun/VirtualBox/Lin/Ver", value:Ver);
      if(version_is_less(version:Ver, test_version:"3.2.0"))
      {
        register_cpe(tmpVers:Ver, tmpExpr:"^(3\..*)",
                   tmpBase:"cpe:/a:sun:virtualbox:", binFile:executableFile);
        register_cpe(tmpVers:Ver, tmpExpr:"^([0-2]\..*)",
                   tmpBase:"cpe:/a:sun:xvm_virtualbox:", binFile:executableFile);
      }
      else
      {
        register_cpe(tmpVers:Ver, tmpExpr:"^([3-9]\..*)",
                   tmpBase:"cpe:/a:oracle:vm_virtualbox:", binFile:executableFile);
      }
    }
  }
}

ssh_close_connection();
