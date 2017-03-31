###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libre_office_detect_lin.nasl 2833 2016-03-11 08:36:30Z benallard $
#
# LibreOffice Version Detection (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script finds the installed LibreOffice version and saves the
  result in KB.";

if(description)
{
  script_id(902701);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2833 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 09:36:30 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("LibreOffice Version Detection (Linux)");
  script_summary("Set the version of LibreOffice in KB");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902701";
SCRIPT_DESC = "LibreOffice Version Detection (Linux)";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}


## Confirm Linux, as SSH can be installed on Windows as well
result = get_kb_item( "ssh/login/uname" );
if("Linux" >!< result){
  exit(0);
}

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

officeName = find_bin(prog_name:"libreoffice", sock:sock);
foreach binary_officeName (officeName)
{
  ## Get the version
  officeVer = get_bin_version(full_prog_name:chomp(binary_officeName),
                            version_argv:"-help",
                            ver_pattern:"LibreOffice ([0-9.]+)", sock:sock);
  if(officeVer[1])
  {
    if(officeVer[2] != NULL)
    {
      buildVer = eregmatch(pattern:"Build.?([0-9.]+)", string:officeVer[2]);
      if(buildVer[1] != NULL)
      {
        tmp_version = officeVer[1] + "." + buildVer[1];
        set_kb_item(name:"LibreOffice/Linux/Ver", value:tmp_version);
        log_message(data:"LibreOffice version " + officeVer[1] + "." +
                    buildVer[1] + " running at location " + binary_officeName
                     + " was detected on the host");

         ## build cpe and store it as host_detail
        register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:libreoffice:libreoffice:");

      }
    }
    else
    {
      set_kb_item(name:"LibreOffice/Linux/Ver", value:officeVer[1]);
      log_message(data:"LibreOffice version " + officeVer[1] +
                    " running at location " + binary_officeName +
                    " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:officeVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:libreoffice:libreoffice:");

    }
  }
}
close(sock);
ssh_close_connection();
