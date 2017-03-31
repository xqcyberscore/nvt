##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_django_detect_lin.nasl 2836 2016-03-11 09:07:07Z benallard $
#
# Django Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_summary = "This script detects the installed version of Django and sets the
  result in KB.";

if(description)
{
  script_id(800923);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2836 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:07:07 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Django Version Detection (Linux)");
  script_summary("Set Version of Django in KB");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800923";
SCRIPT_DESC = "Django Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

getPath = find_file(file_name:"django-admin.py", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);

foreach binaryFile (getPath)
{
  djangoVer = get_bin_version(full_prog_name:chomp(binaryFile), sock:sock,
                              version_argv:"--version", ver_pattern:"^[0-9.]+");

  if(djangoVer[0] != NULL)
  {
    set_kb_item(name:"Django/Linux/Ver", value:djangoVer[0]);
    log_message(data:"Django version " + djangoVer[0] + " running at location " 
                       + binaryFile + " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:djangoVer[0], exp:"^([0-9.]+)", base:"cpe:/a:django_project:django:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
