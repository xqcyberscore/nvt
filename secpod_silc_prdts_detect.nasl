###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_silc_prdts_detect.nasl 8115 2017-12-14 07:30:22Z teissa $
#
# SILC Products Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_summary = "This script detects the installed version of SILC Products
  and sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900950");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8115 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-14 08:30:22 +0100 (Thu, 14 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SILC Products Version Detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900950";
SCRIPT_DESC = "SILC Products Version Detection";

silc_sock = ssh_login_or_reuse_connection();
if(!silc_sock){
  exit(0);
}

# Set the SILC-Client version.
paths = find_file(file_name:"silc", file_path:"/", useregex:TRUE,
                                   regexpar:"$", sock:silc_sock);
foreach clntBin (paths)
{
  clntVer= get_bin_version(full_prog_name:chomp(clntBin), sock:silc_sock,
               version_argv:"--version", ver_pattern:"Client ([0-9.]+)");

  if(clntVer[1] != NULL){
    set_kb_item(name:"SILC/Client/Ver", value:clntVer[1]);
    log_message(data:"SILC version " + clntVer[1] + " running at location " +
                       clntBin +  " was detected on the host");
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:clntVer[1], exp:"^([0-9.]+)", base:"cpe:/a:silcnet:silc_client:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
