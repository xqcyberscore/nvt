###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sjs_access_manager_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# Sun Java System Access Manager Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900194");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9996 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sun Java System Access Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : "This script detects the installed version of Access Manager and
  sets the version in KB.");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Sun Java System Access Manager Version Detection";

am_port = get_http_port(default:8080);

foreach dir (make_list("/", "/amserver"))
{
  sndReq = http_get(item:string(dir, "/UI/Login.jsp"), port:am_port);
  rcvRes = http_send_recv(port:am_port, data:sndReq);

  if(egrep(pattern:"Sun Java System Access Manager .*", string:rcvRes) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    amVer = eregmatch(pattern:"X-DSAMEVersion: ([0-9]\.[0-9.]+(.?[a-zQ0-9]+)?)",
                      string:rcvRes);

    if(amVer[1] != NULL)
    {
       amVer = ereg_replace(pattern:" ", string:amVer[1], replace:".");
       tmp_version = amVer + " under " + dir;
       set_kb_item(name:"www/"+ am_port + "/Sun/JavaSysAccessMang",
                  value:tmp_version);
       log_message(data:"Sun Java System Access Manager version " + amVer +
                          " running at location " + dir +
                          " was detected on the host");

       cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_access_manager:");
       if(!isnull(cpe))
          register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
    }
  }
}
