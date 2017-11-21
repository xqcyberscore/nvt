###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_informix_dynamic_server_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# IBM Informix Dynamic Server Version Detection (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_summary = "This script finds the installed IBM Informix Dynamic Server version
  and saves the version in KB.";

if(description)
{
  script_id(902547);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Informix Dynamic Server Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902547";
SCRIPT_DESC = "IBM Informix Dynamic Server Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## get the possible paths
paths = find_bin(prog_name:"oninit", sock:sock);
foreach bin (paths)
{
  ## check for each path
  version = get_bin_version(full_prog_name:chomp(bin), sock:sock, version_argv:"-V",
                            ver_pattern:"IBM Informix Dynamic Server Version ([0-9.]+)");

  if(version[1] != NULL)
  {
    ## Set IBM Informix Dynamic Server Version in KB
    set_kb_item(name:"IBM/Informix/Dynamic/Server/Lin/Ver", value:version[1]);
    log_message(data:"IBM Informix Dynamic Server " + version[1] +
                         " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:ibm:informix_dynamic_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
close(sock);
