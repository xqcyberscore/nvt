###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Foxit Reader Version Detection (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809332");
  script_version("$Revision: 7823 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2016-11-08 17:20:13 +0530 (Tue, 08 Nov 2016)");
  script_name("Foxit Reader Version Detection (Linux)");
  script_tag(name : "summary" , value : "Detection of installed version of
  Foxit Reader on Linux.

  The script logs in via ssh, searches for foxitreader and queries the
  version from 'FoxitReader' file.");
  
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

##Variable initialization
FoxitVer = 0;
sock = 0;
Foxit_Name = "";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

Foxit_Name = find_file(file_name:"FoxitReader", file_path:"/opt/", useregex:TRUE,
                     regexpar:"$", sock:sock);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("ReaderLite4Linux.*[0-9\\.\\+].*updater:");

foreach binaryName(Foxit_Name)
{
  binaryName = chomp(binaryName);

  arg = garg[0]+" "+garg[1]+" "+garg[2]+" "+
            raw_string(0x22)+garg[3]+raw_string(0x22)+" "+binaryName;

  ## Grep the version from cmd
  FoxitVer = get_bin_version(full_prog_name:grep, version_argv:arg, ver_pattern:"", sock:sock);
  if(FoxitVer[1]){
    FoxitVer = FoxitVer[1];
  }
  else {
    exit(0);
  }

  ##Replace non readble chars with ''
  FoxitVer = str_replace(find:raw_string(0x00), replace:"",string:FoxitVer);

  ##Match the version
  FoxitVer = eregmatch(pattern:"ReaderLite4Linux([0-9.]+)", string:FoxitVer);  
  if(FoxitVer[1] != NULL)
  {
    set_kb_item(name:"Foxit/Reader/Linux/Ver", value:FoxitVer[1]);
 
    ## build cpe
    cpe = build_cpe(value:FoxitVer[1], exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
    if(!cpe)
         cpe = "cpe:/a:foxitsoftware:reader";
    
    register_product(cpe:cpe, location:binaryName);
    log_message(data: build_detection_report(app:"Foxit Reader",
                                             version: FoxitVer[1],
                                             install: binaryName,
                                             cpe: cpe,
                                             concluded: FoxitVer[1]));
    close(sock);
    exit(0);
  }
}

close(sock);
ssh_close_connection();
