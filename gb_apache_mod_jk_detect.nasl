##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_jk_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# Apache mod_jk Module Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800279");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9996 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache mod_jk Module Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mod_jk/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : "This script detects the installed version of Apache mod_jk Module
  and saves the result in KB.");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if("mod_jk" >< banner)
{
  version = eregmatch(pattern:"mod_jk/([0-9.]+)", string:banner);
  if(version[1] != NULL)
  {
    set_kb_item(name:"www/" + port + "/Apache/Mod_Jk", value:version[1]);
    set_kb_item(name:"apache_modjk/installed", value:TRUE);
    log_message(port:port,data:"Mod JK version " + version[1] + " was detected on the host");

    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_jk:");
    if(isnull(cpe))
      cpe = 'cpe:/a:apache:mod_jk';

    register_product(cpe:cpe, location:port + '/tcp', port:port);
  }
}

exit(0);