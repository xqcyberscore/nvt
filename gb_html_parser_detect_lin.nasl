###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_html_parser_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# HTML Parser Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_summary = "The script detects the installed version of HTML Parser and sets the
  reuslt into KB.";

if(description)
{
  script_id(801038);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTML Parser Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801038";
SCRIPT_DESC = "HTML Parser Version Detection (Linux)";

parserSock = ssh_login_or_reuse_connection();
if(!parserSock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:parserSock);
grep = chomp(grep[0]);
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("XS_VERSION.*");

parserName = find_file(file_name:"Parser.so", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:parserSock);

foreach binaryName (parserName)
{
  binaryName = chomp(binaryName);
  if(islocalhost())
  {
    garg[4] = binaryName;
    arg = garg;
  }
  else
  {
    arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
          garg[3] + raw_string(0x22) + " " + binaryName;
  }

  parserVer = get_bin_version(full_prog_name:grep, version_argv:arg,
                              ver_pattern:"XS_VERSION.*", sock:parserSock);
  if(parserVer[1] != NULL)
  {
    parserVer = chomp(parserVer[1]);
    parserVer = str_replace(find:raw_string(0x00), replace:"",string:parserVer);

    if("HTML::Parser" >< parserVer || ("bootstrap parameter" >< parserVer))
    {
      parserVer = eregmatch(pattern:"([0-9.]+)", string:parserVer);
      if(parserVer[1])
      {
        set_kb_item(name:"HTML-Parser/Linux/Ver", value:parserVer[1]);
        log_message(data:"HTML-Parser version " + parserVer[1] + " was detected on the host");
  
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:parserVer[1], exp:"^([0-9.]+)", base:"cpe:/a:derrick_oswald:html-parser:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}
ssh_close_connection();
