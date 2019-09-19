###############################################################################
# OpenVAS Vulnerability Test
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
  script_version("2019-09-16T11:52:11+0000");
  script_tag(name:"last_modification", value:"2019-09-16 11:52:11 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LimeSurvey Version Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");

  script_tag(name:"summary", value:"Detection of LimeSurvey

The script sends a connection request to the server and attempts to detect LimeSurvey.");

  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.limesurvey.org");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

surveyPort = get_http_port(default:80);
if (!can_host_php(port:surveyPort)) exit(0);

foreach dir( make_list_unique("/limesurvey", "/phpsurveyor", "/survey", "/PHPSurveyor", cgi_dirs( port:surveyPort ) ) ) {

  rep_dir = dir;
  if (dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port: surveyPort);

  if ('meta name="generator" content="LimeSurvey http://www.limesurvey.org"' >< rcvRes) {
    version = "unknown";

    url = dir + "/docs/release_notes.txt";
    req = http_get(item: url, port: surveyPort);
    res = http_keepalive_send_recv(port:surveyPort, data:req);

    # Changes from 2.6.6LTS (build 171111) to 2.6.7LTS (build 171208) Feb 23, 2018
    # Changes from 2.50+ (build 160816) to 2.50+ (build 160817) Aug 17, 2016
    # Changes from 2.70.0 (build 170921) to 2.71.0 (build 170925) Sept 25, 2017
    # Changes from 3.0.0-beta.1 (build 170720) to 3.0.0-beta.2 (build 170810) Aug 10, 2017
    # Changes from 1.87RC1 (build 7886) to 1.87RC2 (build 7922) [18-11-2009] - Legend: + new feature, # update feature, - bug fix
    # Changes from 0.992 to 0.993
    surveyVer = eregmatch(pattern: "Changes from [^)]+\)? to ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)?", string: res);
    if (!isnull(surveyVer[1])) {
      version = surveyVer[1];
      if (!isnull(surveyVer[2]))
        version += surveyVer[2];
      concUrl = url;
    }

    set_kb_item(name: "limesurvey/installed", value: TRUE);

    cpe = "cpe:/a:limesurvey:limesurvey";
    if (version != "unknown") {
      if (!isnull(surveyVer[2])) {
        update_version = ereg_replace(string: surveyVer[2], pattern: "[-.]", replace: "");
        cpe += ":" + surveyVer[1] + ":" + update_version;
      } else {
        cpe += ":" + surveyVer[1];
      }
    }

    register_product(cpe: cpe, location: rep_dir, port: surveyPort, service: "www");

    log_message(data: build_detection_report(app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe,
                                             concluded: surveyVer[0], concludedUrl: concUrl),
                port: surveyPort);
  }
  # PHPSurveyor or Surveyor are the product name of old LimeSurvey
  else if ("You have not provided a survey identification number" >< rcvRes) {
    version = "unknown";

    url = dir + "/docs/release_notes_and_upgrade_instructions.txt";
    req = http_get(item: url, port: surveyPort);
    res = http_keepalive_send_recv(port:surveyPort, data:req);

    surveyVer = eregmatch(pattern:"Changes from ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)? to ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)?", string:res);
    if (!isnull(surveyVer[3])) {
      version = surveyVer[3];
      if (!isnull(surveyVer[4]))
        version += surveyVer[4];
      concUrl = url;
    }

    set_kb_item(name: "limesurvey/installed", value: TRUE);

    cpe = "cpe:/a:limesurvey:limesurvey";
    if (version != "unknown") {
      if (!isnull(surveyVer[4])) {
        update_version = ereg_replace(string: surveyVer[4], pattern: "[-.]", replace: "");
        cpe += ":" + surveyVer[3] + ":" + update_version;
      } else {
        cpe += ":" + surveyVer[3];
      }
    }

    register_product(cpe: cpe, location: rep_dir, port: surveyPort, service: "www");

    log_message(data: build_detection_report(app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe,
                                             concluded: surveyVer[0], concludedUrl: concUrl),
                port: surveyPort);
  }
}

exit(0);
