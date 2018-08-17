###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_overlook_detect.nasl 11028 2018-08-17 09:26:08Z cfischer $
#
# OPEN IT OverLook Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902513");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OPEN IT OverLook Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of OverLook on remote host and
  sets the KB.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "OPEN IT OverLook Version Detection";

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/overlook"))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/src/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(">OverLook by Open IT<" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/README"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if("OverLook" >< rcvRes)
    {
      ver = eregmatch(pattern:"Version \.+ ([0-9.]+)", string:rcvRes);
      if(ver[1])
      {
        tmp_version = ver[1] + " under " + dir;
        set_kb_item(name:"www/" + port + "/OverLook", value:tmp_version);
        log_message(data:"OverLook version " + ver[1] +
                           " running at location "  + dir +
                           " was detected on the host", port:port);

        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:openit:overlook:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      }
    }
  }
}
