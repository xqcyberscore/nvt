###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_machines_forum_detect.nasl 4316 2016-10-20 15:26:13Z cfi $
#
# Simple Machines Forum Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated by Antu Sanadi <santu@secpod.com> on 2011-06-23
# - Updated to detect the recent versions
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800557");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4316 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-20 17:26:13 +0200 (Thu, 20 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Simple Machines Forum Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Simple Machines Forum
  and sets the result in KB.");

  script_xref(name:"URL", value:"http://www.simplemachines.org/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);

rootInstalled = 0;

foreach dir (make_list_unique("/", "/community", "/smf", "/smf1", "/smf2", "/forum", "/board", "/sm_forum", cgi_dirs(port:port))) {

  if( rootInstalled) break;
  installed = 0;

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);
  if("Powered by SMF" >< rcvRes || ">Simple Machines<" >< rcvRes) {
    installed = 1;
  } else {
    rcvRes = http_get_cache(item: dir + "/", port:port);
    if("Powered by SMF" >< rcvRes || ">Simple Machines<" >< rcvRes) {
      installed = 1;
    }
  }

  if(installed) {

    smfVer = "unknown";
    if (dir == "") rootInstalled = 1;

    version = eregmatch(pattern:">SMF ([0-9.]+).?(RC[0-9])?</a>", string:rcvRes);
    if(version[1] != NULL) {
      if(version[2] == NULL) {
        smfVer = version[1];
      } else {
        smfVer = version[1] + "." + version[2];
      }
    } else {
      version = eregmatch(pattern:">Powered by SMF ([0-9.]+).?(RC[0-9])?</a>", string:rcvRes);
      if(version[1] != NULL) {
        if(version[2] == NULL) {
          smfVer = version[1];
        } else {
          smfVer = version[1] + "." + version[2];
        }
      } else {
        #If version is hidden try some common backup file names
        foreach file (make_list("/index.php~", "/Sources/Subs.php~")) {
          sndReq = http_get(item: dir + file, port:port);
          rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

          version = eregmatch(pattern:"\* @version ([0-9.]+).?(RC[0-9])?", string:rcvRes);
          if(version[1] != NULL) {
            if(version[2] == NULL) {
              smfVer = version[1];
            } else {
              smfVer = version[1] + "." + version[2];
            }
            break;
          }
        }
      }
    }

    set_kb_item(name:"SMF/installed",value:TRUE);
    tmp_version = smfVer + " under " + install;
    set_kb_item(name:"www/" + port + "/SMF", value:tmp_version);

    ## Build CPE
    cpe = build_cpe(value:smfVer, exp:"^([0-9.]+)(RC[0-9])?", base:"cpe:/a:simplemachines:smf:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:simplemachines:smf';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"SMF",
                                               version:smfVer,
                                               install:install,
                                               cpe:cpe,
                                               concluded:version[0] ),
                                               port:port );
  }
}

exit( 0 );
