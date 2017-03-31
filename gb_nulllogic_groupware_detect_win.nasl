###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nulllogic_groupware_detect_win.nasl 5390 2017-02-21 18:39:27Z mime $
#
# NullLogic Groupware Version Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script detects the installed version of NullLogic Groupware
  and sets the result in KB.";

if(description)
{
  script_id(800905);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NullLogic Groupware Version Detection");
  script_summary("Set Version of NullLogic Groupware in KB");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("NullLogic_Groupware/banner");
  script_require_ports("Services/www", 4110);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800905";
SCRIPT_DESC = "NullLogic Groupware Version Detection";

ngPort = get_http_port(default:4110);
if(!ngPort){
  ngPort = 4110;
}

if(!get_port_state(ngPort)){
  exit(0);
}

banner = get_http_banner(port:ngPort);
if("NullLogic Groupware" >!< banner){
  exit(0);
}

ngVer = eregmatch(pattern:"NullLogic Groupware ([0-9.]+)" , string:banner);
if(ngVer[1] != NULL)
{
  set_kb_item(name:"NullLogic-Groupware/Ver", value:ngVer[1]);
  log_message(data:"NullLogic Groupware version " + ngVer[1] +
                         " was detected on the host");
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:ngVer[1], exp:"^([0-9.]+)", base:"cpe:/a:nulllogic:groupware:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
