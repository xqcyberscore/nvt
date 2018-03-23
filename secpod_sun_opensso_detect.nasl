###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_opensso_detect.nasl 9185 2018-03-23 09:42:17Z cfischer $
#
# Sun/Oracle OpenSSO Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated to detect new versions.
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900817");
  script_version("$Revision: 9185 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-23 10:42:17 +0100 (Fri, 23 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_name("Sun/Oracle OpenSSO Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Sun/Oracle OpenSSO.
  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

am_port = get_http_port(default:8080);

foreach dir (make_list("/",  "/opensso"))
{
  sndReq = http_get(item:string(dir, "/UI/Login.jsp"), port:am_port);
  rcvRes = http_send_recv(port:am_port, data:sndReq);

  if("OpenSSO" >< rcvRes && egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes))
  {
    ssoVer = eregmatch(pattern:"X-DSAMEVersion:( Enterprise | Snapshot Build | Oracle OpenSSO )?([0-9]\.[0-9.]+([a-zA-Z0-9 ]+)?)", string:rcvRes);
    if(ssoVer[2] != NULL)
    {
      ssoVer = ereg_replace(pattern:" ", string:ssoVer[2], replace:".");
      tmp_version = ssoVer + " under " + dir;

      set_kb_item(name:"www/"+ am_port + "/Sun/OpenSSO", value:tmp_version);
      set_kb_item(name:"Oracle/OpenSSO/installed", value:TRUE);

      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:oracle:opensso:");
      if(isnull(cpe))
       cpe = 'cpe:/a:oracle:opensso';

      register_product(cpe:cpe, location:am_port + '/tcp', port:am_port);

      log_message(data: build_detection_report(app:"Sun/Oracle OpenSSO",
                                               version:tmp_version,
                                               install: am_port + '/tcp',
                                               cpe:cpe,
                                               concluded: tmp_version),
                                               port:am_port);
    }
  }
}
