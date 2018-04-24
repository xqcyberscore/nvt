###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_detection_linux_900037.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Opera Version Detection for Linux
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# Modified to detect Beta Versions
#  - Sharath S <sharaths@secpod.com> On 2009-09-02
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-04-06
#  - Updated according CR 57 and updated to get version from Ubuntu and Debian.
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
################################################################################

tag_summary = "Detection of installed version of Opera.

The script logs in via ssh, searches for executable 'opera' and
greps the version executable found.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900037";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Opera Version Detection for Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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

## Variable Initialization
sock = 0;
result = "";
operaVer = "";
operaName = "";
binaryName = "";
checkdupOpera = "";
operaBuildVer = "";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Opera [0-9]\\+\\.[0-9]\\+");
garg[5] = string("Internal\\ build\\ [0-9]\\+");
garg[6] = string("Build\\ number:.*");

operaName = find_file(file_name:"opera", file_path:"/", useregex:TRUE,
                      regexpar:"$", sock:sock);


foreach binaryName(operaName)
{
  binaryName = chomp(binaryName);

  ## Grep the version from Opera cmd
  operaVer = get_bin_version(full_prog_name:binaryName, version_argv:"-version",
                             ver_pattern:"Opera ([0-9.]+) (Build ([0-9]+))?", sock:sock);

  ## Get the build version if found
  if(operaVer && operaVer[1] && operaVer[3]){
    operaBuildVer = operaVer[1] + "." + operaVer[3];
  }

  ## Get the opera version
  if(operaVer && operaVer[1]){
     operaVer = operaVer[1];
  }

  ## Get the version from file if cmd not found
  if(!operaVer)
  {
    if(islocalhost())
    {
      garg[4] = binaryName;
      arg1 = garg;
    }
    else
    {
      arg1 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
             garg[3] + raw_string(0x22) + " " + binaryName;
      arg2 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
             garg[5] + raw_string(0x22) + " " + binaryName;
      arg3 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
             garg[6] + raw_string(0x22) + " " + binaryName;
     }

     operaVer = get_bin_version(full_prog_name:grep, version_argv:arg1,
                                ver_pattern:"Opera ([0-9]+\.[0-9]+)", sock:sock);

     operaVer = operaVer[1];
  }

  if(!isnull(operaVer))
  {
    ## Check if version is already set
    if(operaVer + ", ">< checkdupOpera){
      continue;
    }

    checkdupOpera  +=  operaVer + ", ";

    ## Set the KB version
    set_kb_item(name:"Opera/Linux/Version", value:operaVer);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:operaVer, exp:"^([0-9.]+)", base:"cpe:/a:opera:opera:");
    if(!isnull(cpe))
       register_product(cpe:cpe, location:binaryName);

    log_message(data:'Detected Opera version: ' + operaVer +
      '\nLocation: ' + binaryName +
      '\nCPE: '+ cpe +
      '\n\nConcluded from version identification result:\n' + operaVer);

    ## If build version not found then get it from file
    if(!operaBuildVer)
    {
      operaBuildVer = get_bin_version(full_prog_name:grep, version_argv:arg2,
                      ver_pattern:"Internal [B|b]uild ([0-9]+)", sock:sock);

      if(!operaBuildVer[1])
      {
        operaBuildVer = get_bin_version(full_prog_name:grep, version_argv:arg3,
                                        ver_pattern:"Build number:.*", sock:sock);
        operaBuildVer = operaBuildVer[1] - raw_string(0x00);
        operaBuildVer = eregmatch(pattern:"Build number:([0-9]+)",
                                  string:operaBuildVer);
        if(operaBuildVer && operaBuildVer[1]){
          operaBuildVer = operaVer + operaBuildVer[1];
        }
      }
    }

    if(!isnull(operaBuildVer))
    {
      buildVer = operaBuildVer;
      set_kb_item(name:"Opera/Build/Linux/Ver", value:buildVer);
      ssh_close_connection();
    }
  }
}
close(sock);
