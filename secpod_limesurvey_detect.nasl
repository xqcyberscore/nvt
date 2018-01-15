###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_limesurvey_detect.nasl 8370 2018-01-11 09:44:52Z cfischer $
#
# LimeSurvey Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900352");
  script_version("$Revision: 8370 $");
  script_tag(name: "last_modification", value: "$Date: 2018-01-11 10:44:52 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name: "creation_date", value: "2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name: "qod_type", value: "remote_banner");

  script_name("LimeSurvey Version Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");

  script_tag(name: "summary", value: "Detection of LimeSurvey

The script sends a connection request to the server and attempts to detect LimeSurvey.");

  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

surveyPort = get_http_port(default:80);
if( ! can_host_php( port:surveyPort ) ) exit( 0 );

foreach dir( make_list_unique("/limesurvey", "/phpsurveyor", "/survey", "/PHPSurveyor", cgi_dirs( port:surveyPort ) ) ) {

  rep_dir = dir;
  if (dir == "/") dir = "";

  rcvRes = http_get_cache(item: string(dir, "/index.php"), port: surveyPort);

  if ('meta name="generator" content="LimeSurvey http://www.limesurvey.org"' >< rcvRes) {
    version = string("unknown");
    
    req = http_get(item: string(dir, "/docs/release_notes.txt"), port: surveyPort);
    res = http_keepalive_send_recv(port:surveyPort, data:req); 

    if (res != NULL) {
      surveyVer = eregmatch(pattern: "Changes from ([]0-9.RCa-z+ ()]+) to ([]0-9.RCa-z+ ()]+)",
                            string: res);
      if(surveyVer[2] != NULL) {
        version = chomp(surveyVer[2]);
        version = str_replace(string: version, find: " ", replace: "_");
        version = ereg_replace(string: version, pattern: "(\(|\))", replace: "");
      }
    }

    set_kb_item(name:"www/" + surveyPort + "/LimeSurvey",
                    value:version);
    set_kb_item(name: "limesurvey/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "([]0-9.RCa-z+ ()_]+)", 
                    base: "cpe:/a:limesurvey:limesurvey:");
    if (isnull(cpe))
      cpe = "cpe:/a:limesurvey:limesurvey";

    register_product(cpe: cpe, location: rep_dir, port: surveyPort);

    log_message(data: build_detection_report(app: "LimeSurvey", version: version,
                                             install: rep_dir, cpe: cpe), port: surveyPort);
  }
  # PHPSurveyor or Surveyor are the product name of old LimeSurvey
  else if ("You have not provided a survey identification number" >< rcvRes) {
    version = string("unknown");

    req = http_get(item: string(dir, "/docs/release_notes_and_upgrade_instructions.txt"),
                   port: surveyPort);
    res = http_keepalive_send_recv(port:surveyPort, data:req);

    if (res != NULL) {
      surveyVer = eregmatch(pattern:"Changes from ([0-9.]+) to ([0-9.]+)", string:res);
      if(surveyVer[2] != NULL)
        version = chomp(surveyVer[2]);
    }

    set_kb_item(name:"www/" + surveyPort + "/LimeSurvey", value:version);
    set_kb_item(name: "limesurvey/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "([0-9.]+)", base: "cpe:/a:limesurvey:limesurvey:");
    if (isnull(cpe))
      cpe = "cpe:/a:limesurvey:limesurvey";

    register_product(cpe: cpe, location: rep_dir, port: surveyPort);

    log_message(data: build_detection_report(app: "LimeSurvey", version: version,
                                             install: rep_dir, cpe: cpe), port: surveyPort);
  }
}

exit(0);
