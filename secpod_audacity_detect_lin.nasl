###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_audacity_detect_lin.nasl 8087 2017-12-12 13:12:04Z teissa $
#
# Audacity Version Detection (Linux)
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

tag_summary = "This script detects the installed version of Audacity and sets
  the reuslt in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900306");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8087 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Audacity Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900306";
SCRIPT_DESC = "Audacity Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_file(file_name:"README.txt",file_path:"/doc/audacity/",
                  useregex:TRUE, regexpar:"$", sock:sock);
foreach binName (paths)
{
  audacityVer = get_bin_version(full_prog_name:"cat", version_argv:binName,
                                ver_pattern:"Version ([0-9]\.[0-9]\.[0-9]+)",
                                sock:sock);
  if("Audacity" >!< audacityVer){
    continue;
  }

  if(audacityVer[1] != NULL)
  {
    set_kb_item(name:"Audacity/Linux/Ver", value:audacityVer[1]);
    log_message(data:"Audacity version " + audacityVer[1] +
             " running at location " + binName + " was detected on the host");
    ssh_close_connection();
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:audacityVer[1], exp:"^([0-9.]+)", base:"cpe:/a:audacity:audacity:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
