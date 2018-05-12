###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_nas_photo_station_detect.nasl 9802 2018-05-11 11:53:28Z santu $
#
# QNAP QTS Photo Station Detection 
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813164");
  script_version("$Revision: 9802 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-11 13:53:28 +0200 (Fri, 11 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-03 19:51:43 +0530 (Thu, 03 May 2018)");
  script_name("QNAP QTS Photo Station Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  QNAP QTS Photo Station.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!qtsPort = get_http_port(default:80)){
  exit(0);
}

dirs = make_list("/photo/", "/photo/gallery/", "/gallery/");

foreach dir (dirs)
{
  req = http_get_req( url:dir, port:qtsPort, add_headers:make_array("Accept-Encoding", "gzip, deflate"));
  res = http_keepalive_send_recv(port:qtsPort, data:req);

  ##Handle redirection
  if(res =~ "^HTTP/1.. 30.")
  {
    url = eregmatch(pattern: 'Location: ([^\r\n]+)', string: res);
    if(url[1])
    {
      new_url = url[1];
      req = http_get_req( url:new_url, port:qtsPort);
      res = http_keepalive_send_recv(port:qtsPort, data:req);
      if(!(res =~ "HTTP/1.. 200 OK")){
        continue ;
      } 
    }
  }

  ##Confirm Photo Station
  if(res =~ "HTTP/1.. 200 OK" && "title>Photo Station</title" >< res)
  {
    url = eregmatch(pattern:"'\.js\?([0-9.]+)", string:res);
    new_url = dir + "/lang/ENG.js?" + url[1] ;
    req = http_get_req( url:new_url, port:qtsPort);
    res = http_keepalive_send_recv(port:qtsPort, data:req);

    ##Confirm for QNAP QTS
    if(res =~ "HTTP/1.. 200 OK" && "QTS Login" >< res && res =~ "COPYRIGHT=.*QNAP Systems" &&
      "LANG_QTS" >< res)
    {
      photoVer = "Unknown";
      set_kb_item(name:"QNAP/QTS/PhotoStation/detected", value:TRUE);

      ##Try to get Photo Station version
      url = dir + "/api/user.php" ;
      req = http_get_req( url:url, port:qtsPort);
      res = http_keepalive_send_recv(port:qtsPort, data:req);
      if(res =~ "HTTP/1.. 200 OK" && "status" >< res && "timestamp" >< res)
      {
        version = eregmatch(pattern:'<appVersion>([0-9.]+)</appVersion><appBuildNum>([0-9]+)<', string:res);
        baseQTSVersion = eregmatch(pattern:'<builtinFirmwareVersion>([0-9.]+)</builtinFirmwareVersion>', string:res);
        if(version[1])
        {
          photoVer = version [1];
          set_kb_item(name:"QNAP/QTS/PhotoStation/version", value: photoVer);
          if(version[2]){
            photoBuild = version [2];
            set_kb_item(name:"QNAP/QTS/PhotoStation/build", value: photoBuild);
          }
          if(baseQTSVersion[1]){
            baseQTSVer = baseQTSVersion[1];
            set_kb_item(name:"QNAP/QTS/PS/baseQTSVer", value: baseQTSVer);
          }

          cpe = build_cpe(value:photoVer, exp:"^([0-9.]+)", base:"cpe:/o:qnap:qts_photo_station:");
          if(isnull(cpe))
            cpe = "cpe:/o:qnap:qts_photo_station:";

          register_product(cpe:cpe, location:dir, port:qtsPort);

          log_message(data: build_detection_report(app:"QNAP QTS Photo Station",
                                           version:photoVer,
                                           install:dir,
                                           cpe:cpe,
                                           concluded: photoVer + " Build " + photoBuild + " on QTS "+ baseQTSVer),
                                           port:qtsPort);
          exit(0);
        }
      }
    }
  }
}
exit(0);
