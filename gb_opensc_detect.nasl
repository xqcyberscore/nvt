###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opensc_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# OpenSC Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800369");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenSC Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : "This script detects the version of OpenSC and sets the
  result in the KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "OpenSC Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

openscName = find_file(file_name:"opensc-config", file_path:"/",
                       useregex:TRUE, regexpar:"$", sock:sock);
if(openscName != NULL)
{
  foreach binName (openscName)
  {
    binName = chomp(binName);
    openscVer = get_bin_version(full_prog_name:binName, ver_pattern:"([0-9.]+)",
                                version_argv:"--version", sock:sock);
    if(openscVer[0] != NULL)
    {
      set_kb_item(name:"OpenSC/Ver", value:openscVer[0]);
      log_message(data:"OpenSC version " + openscVer[0] + " running at location "
                          + binName + " was detected on the host");
      ssh_close_connection();

      cpe = build_cpe(value:openscVer[0], exp:"^([0-9.]+)", base:"cpe:/a:opensc-project:opensc:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
ssh_close_connection();
