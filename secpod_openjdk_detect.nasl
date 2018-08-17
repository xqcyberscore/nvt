###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openjdk_detect.nasl 11029 2018-08-17 09:30:04Z cfischer $
#
# OpenJDK Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900334");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11029 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:30:04 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenJDK Version Detection");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");

  script_tag(name:"summary", value:"This script detects the installed version of OpenJDK and sets
  the reuslt in KB.");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "OpenJDK Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"java", sock:sock);
foreach binName (paths)
{
  if( chomp(binName) == "" ) continue;
  ver = get_bin_version(full_prog_name:chomp(binName), version_argv:"-version",
                        ver_pattern:"OpenJDK.*([0-9]\.[0-9]\.[0-9._]+)-?([b0-9]+)?",
                        sock:sock);

  dump = ver;

  if("OpenJDK" >< ver)
  {
    if((ver[1] && ver[2]) != NULL){
      ver = ver[1] + "." + ver[2];
    }
    else{
      ver = ver[1];
    }

    if(ver != NULL)
    {
      set_kb_item(name:"OpenJDK/Ver", value:ver);
      ssh_close_connection();

      cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:sun:openjdk:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      log_message(data:'Detected OpenJDK version: ' + ver +
        '\nLocation: ' + binName +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + dump[max_index(dump)-1]);

      exit(0);
    }
  }
}
ssh_close_connection();
