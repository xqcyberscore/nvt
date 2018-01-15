###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ghostscript_detect_lin.nasl 8370 2018-01-11 09:44:52Z cfischer $
#
# Ghostscript Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
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

tag_summary = "Detection of installed version of Ghostscript.

The script logs in via ssh, searches for executable 'gs' and
queries the found executables via command line option '--help'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900541";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8370 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 10:44:52 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Ghostscript Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 secPod");
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
  if (defined_func("error_message"))
    error_message(port:0, data:"Failed to open ssh port.");
  exit(-1);
}

gsName = find_file(file_name:"gs", file_path:"/", useregex:TRUE,
                   regexpar:"$", sock:sock);
foreach executableFile(gsName)
{
  executableFile = chomp(executableFile);
  gsVer = get_bin_version(full_prog_name:executableFile, version_argv:"--help",
                          ver_pattern:"Ghostscript ([0-9]\.[0-9.]+)", sock:sock);

  if(gsVer[1] != NULL)
  {
    resp = gsVer[max_index(gsVer)-1];
    if("Ghostscript" >< resp && "Artifex Software," >< resp)
    {
      set_kb_item(name:"Ghostscript/Linux/Ver", value:gsVer[1]);

      cpe = build_cpe(value:gsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ghostscript:ghostscript:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

      log_message(data:'Detected Ghostscript version: ' + gsVer[1] +
          '\nLocation: ' + executableFile +
          '\nCPE: '+ cpe +
          '\n\nConcluded from version identification result:\n' + gsVer[1]);
    }
  }
}

ssh_close_connection();
