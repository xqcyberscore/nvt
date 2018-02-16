###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmailer_detect.nasl 8814 2018-02-14 16:51:31Z cfischer $
#
# PHPMailer Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809841");
  script_version("$Revision: 8814 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-14 17:51:31 +0100 (Wed, 14 Feb 2018) $");
  script_tag(name:"creation_date", value:"2016-12-27 15:57:31 +0530 (Tue, 27 Dec 2016)");
  script_name("PHPMailer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of PHPMailer Library.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir(make_list_unique("/PHPMailer-master", "/PHPMailer", "/phpmailer", cgi_dirs(port:port)))
{
  install = dir;
  if(dir == "/") dir = "";

  foreach path (make_list("", "/lib"))
  {
    rcvRes = http_get_cache(item: dir + path + "/composer.json", port:port);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '"name": "phpmailer/phpmailer"' >< rcvRes
                                     && 'class.phpmailer.php' >< rcvRes)
    {
      mailer = TRUE;

      foreach file (make_list("/VERSION", "/version"))
      {
        rcvRes1 = http_get_cache(item: dir + path + file, port:port);

        if(rcvRes1 =~ "^HTTP/1\.[01] 200")
        {
          version = eregmatch(pattern:'\n([0-9.]+)', string: rcvRes1);
          if(version[1])
          {
            version = version[1];
            break;
          }
        }
      }
    }
    if(version){
      break;
    } else {
      continue;
    }
  }

  if(!version)
  {
    rcvRes = http_get_cache(item: dir + "/README", port:port);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && 'class.phpmailer.php' >< rcvRes
                                     && 'PHPMailer!' >< rcvRes)
    {
      mailer = TRUE;
      rcvRes1 = http_get_cache(item: dir + "/changelog.txt", port:port);

      # The "Intial" typo is expected as this typo exists in the changelog.txt
      if(rcvRes1 =~ "^HTTP/1\.[01] 200" && "Intial public release" >< rcvRes1) {
        version = eregmatch(pattern:'Version ([0-9.]+)', string: rcvRes1);
        if(version[1]){
          version = version[1];
        }
      }
    }
  }

  if(!version)
  {
    rcvRes = http_get_cache(item: dir + "/extras", port:port);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && rcvRes =~ "title>Index of.*extras"
                                     && '"EasyPeasyICS.php' >< rcvRes)
    {
      mailer = TRUE;
      rcvRes1 = http_get_cache(item: dir + "/VERSION", port:port);

      if(rcvRes1 =~ "^HTTP/1\.[01] 200")
      {
        version = eregmatch(pattern:'\n([0-9.]+)', string: rcvRes1);
        if(version[1]){
          version = version[1];
        }
      }
    }
  }

  if(mailer && !version){
    version = "unknown";
  }

  if(version)
  {
    set_kb_item(name:"www/" + port + "/phpmailer", value:version);
    set_kb_item(name:"phpmailer/Installed", value:TRUE);

    # CPE not registered yet
    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:phpmailer:phpmailer:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:phpmailer:phpmailer';

    register_product(cpe:cpe, location:install, port:port);

    log_message( data:build_detection_report( app:"PHPMailer",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:port);
    exit(0);
  }
}

exit(0);
