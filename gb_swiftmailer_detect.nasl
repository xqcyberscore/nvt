###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swiftmailer_detect.nasl 4890 2016-12-30 13:26:31Z antu123 $
#
# SwiftMailer Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809772");
  script_version("$Revision: 4890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-30 14:26:31 +0100 (Fri, 30 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-29 17:59:59 +0530 (Thu, 29 Dec 2016)");
  script_name("SwiftMailer Detection");

  script_tag(name:"summary", value:"Detection of SwiftMailer Library.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
phpPort = 0;
rcvRes = "";
version = "";

##Get HTTP Port
if(!phpPort = get_http_port(default:80)){
  exit(0);
}

if(!can_host_php(port:phpPort)) exit(0);

##Iterate over possible paths
foreach dir(make_list_unique("/", "/swiftmailer", "/SwiftMailer", cgi_dirs(port:phpPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  foreach path (make_list("", "/lib"))
  {
    foreach file (make_list("/composer.json", "/README", "/CHANGES", ""))
    {
      ## Send and receive response
      sndReq = http_get(item: dir + path + file, port:phpPort);
      rcvRes = http_send_recv(port:phpPort, data:sndReq);

      ##Confirm application
      if((rcvRes =~ "^HTTP/.* 200 OK") &&
         ('swiftmailer"' >< rcvRes && '"MIT"' >< rcvRes && 'swiftmailer.org"' >< rcvRes) ||
         ("Swift Mailer, by Chris Corbyn" >< rcvRes && "swiftmailer.org" >< rcvRes)||
         ("Swift_Mailer::batchSend" >< rcvRes && "Swiftmailer" >< rcvRes))
      {
        ## Send and receive response
        foreach verfile (make_list("/VERSION", "/version"))
        {
          sndReq1 = http_get(item: dir + path + verfile, port:phpPort);
          rcvRes1 = http_send_recv(port:phpPort, data:sndReq1);

          if(rcvRes1 =~ "^HTTP/.* 200 OK")
          {
            ##Grep for version
            version = eregmatch(pattern:'Swift-([0-9.]+)([A-Za-z0-9]-)?', string: rcvRes1);
            if(version[1])
            {
              version = version[1];
              version = ereg_replace(pattern:"-", string:version, replace:".");

              ## Set the KB value
              set_kb_item(name:"www/" + phpPort + "/swiftmailer", value:version);
              set_kb_item(name:"swiftmailer/Installed", value:TRUE);

              # CPE not registered yet
              cpe = build_cpe( value:version, exp:"([0-9A-Za-z.]+)", base:"cpe:/a:swiftmailer:swiftmailer:");
              if( isnull(cpe ))
                cpe = 'cpe:/a:swiftmailer:swiftmailer';

              register_product(cpe:cpe, location:install, port:phpPort);

              log_message(data:build_detection_report(app:"SwiftMailer",
                                                      version:version,
                                                      install:install,
                                                      cpe:cpe,
                                                      concluded:version),
                                                      port:phpPort);
              exit(0);
            }
          }
        }
      }
    }
  }
}
exit(0);
