##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyadmin_detect_900129.nasl 7000 2017-08-24 11:51:46Z teissa $
# Description: phpMyAdmin Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated by Deependra Bapna <bdeependra@secpod.com> on 2014-12-31
# - To detect the newer versions
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900129");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)");
  script_name("phpMyAdmin Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2008 SecPod");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of phpMyAdmin.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
phpPort = get_http_port(default:80);

#Check if host supports php
if(!can_host_php(port:phpPort)){
  exit(0);
}

# check if there is some kind of "alias" accepting any spelling of "phpmyadmin". If yes, stop after first detection.
check_dirs = make_list("/pHpmyADmiN","/PhPmyAdMin","/phPmYaDmiN","/phpMyadMiN");

alias = TRUE;
ac = 0;

foreach cd ( check_dirs )
{
   rcvRes = http_get_cache(item: cd + "/index.php", port:phpPort);
   if( rcvRes !~ "HTTP/1\.. 200" )
   {
     alias = FALSE;
     ac = 0;
     break;
   }
   ac++;
}

if( ac != 4 ) alias = FALSE;

x = 0;
foreach dir (make_list_unique("/","/phpmyadmin","/phpMyAdmin","/pma", "/PHPMyAdmin", cgi_dirs(port:phpPort)))
{

  if(dir == "/setup") continue;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpPort);

  #check if host is installed with phpmyadmin or not
  if(egrep(pattern:"^Set-Cookie: pma_.*", string:rcvRes)       ||
     egrep(pattern:"^Set-Cookie: phpMyAdmin.*",string:rcvRes)  ||
     egrep(pattern:"phpMyAdmin was unable to read your configuration file",string:rcvRes)  ||
     egrep(pattern:"<title>phpMyAdmin.*", string:rcvRes)       ||
     egrep(pattern:"href=.*phpmyadmin.css.php")                ||
     (egrep(pattern:"pma_password", string:rcvRes) && egrep(pattern:"pma_username", string:rcvRes)))
  {
    phpmaVer = eregmatch(pattern:"phpMyAdmin (([0-9.]+)(-[rc0-9]*)?)", string:rcvRes);
    #if host is installed with newer version of phpmyadmin (>4.2.x)
    if(isnull(phpmaVer[1])) {
      sndReq = http_get(item:string(dir, "/README"), port:phpPort);
      rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq);
      phpmaVer = eregmatch(pattern:"Version (([0-9.]+)(-[rc0-9]*)?)", string:rcvRes1);
      if(isnull(phpmaVer[1])) {
        sndReq = http_get(item:string(dir, "/doc/html/index.html"), port:phpPort);
        rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq);
        phpmaVer = eregmatch(pattern:"phpMyAdmin (([0-9.]+)(-[rc0-9]*)?) documentation", string:rcvRes1);
        if(isnull(phpmaVer[1])) {
          #extra check for bug in debian package 4.2 which shipped a wrong symlink
          sndReq = http_get(item:string(dir, "/docs/html/index.html"), port:phpPort);
          rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq);
          phpmaVer = eregmatch(pattern:"phpMyAdmin (([0-9.]+)(-[rc0-9]*)?) documentation", string:rcvRes1);
          if(isnull(phpmaVer[1])) {
            sndReq = http_get(item:string(dir, "/ChangeLog"), port:phpPort);
            rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq, bodyonly:TRUE);
            if("phpMyAdmin - ChangeLog" >< rcvRes1) phpmaVer = eregmatch(pattern:"(([0-9.]+)(-[rc0-9]*)?) \(", string:rcvRes1);
            if(isnull(phpmaVer[1])) {
              sndReq = http_get(item:string(dir, "/Documentation.html"), port:phpPort);
              rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq);
              phpmaVer = eregmatch(pattern:"phpMyAdmin (([0-9.]+)( -[rc0-9]*)?) Documentation", string:rcvRes1);
              if(isnull(phpmaVer[2])) {
                sndReq = http_get(item:string(dir, "/changelog.php"), port:phpPort);
                rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq, bodyonly:TRUE);
                if("phpMyAdmin - ChangeLog" >< rcvRes1) phpmaVer = eregmatch(pattern:"(([0-9.]+)(-[rc0-9]*)?) \(", string:rcvRes1);
                if(isnull(phpmaVer[1])) {
                  version = "unknown";
                } else {
                  version = phpmaVer[1];
                }
              } else {
                version = phpmaVer[2];
	      }
            } else {
              version = phpmaVer[1];
	    }
          } else {
            version = phpmaVer[1];
          }
        } else {
          version = phpmaVer[1];
        }
      } else {
        version = phpmaVer[1];
      }
    } else {
      version = phpmaVer[1];
    }
    if(dir == "") dir = "/";
    pw_protected=0;

    if(egrep(pattern:"1045", string:rcvRes) ||
       egrep(pattern:"phpMyAdmin was unable to read your configuration file", string:rcvRes)) {
       pw_protected=2; # broken config
    }

    if(egrep(pattern:"pma_username", string:rcvRes) &&
       egrep(pattern:"pma_password", string:rcvRes)) {
       pw_protected=1; # username password required
    }

    tmp_version = version + " under " + dir;
    set_kb_item(name:"www/"+ phpPort + "/phpMyAdmin", value:tmp_version);

    installations[x] = string(tmp_version + ":" + pw_protected + "");
    if( alias ) break;
    x++;
  }
}


if(installations)
{

  set_kb_item(name:"phpMyAdmin/installed",value:TRUE);

  foreach found (installations)
  {
    infos = eregmatch(pattern:"(.*) under (/.*):+([0-2]+)", string:found);
    ver = infos[1];
    dir = infos[2];
    protected = infos[3];

    cpe = build_cpe(value:ver, exp:"^([0-9.]+).*([rc0-9]*)?", base:"cpe:/a:phpmyadmin:phpmyadmin:");
    if(!cpe)
      cpe = 'cpe:/a:phpmyadmin:phpmyadmin';

    if(protected == 0) {
     info = '\n(Not protected by Username/Password)\n';
    }
    else if(protected == 2) {
      info = '\n(Problem with configuration file)\n';
    }

    #check if /setup/ dir is unprotected
    if(dir == "/")
      dir2 = "";
    else
      dir2 = dir;
    sndReq = http_get(item:string(dir2, "/setup/"), port:phpPort);
    rcvRes1 = http_keepalive_send_recv(port:phpPort, data:sndReq);

    if("<title>phpMyAdmin setup</title>" >< rcvRes1) {
      info = '\n(Possible unprotected /setup/ dir identified)\n';
    }

    register_product(cpe:cpe, location:dir, port:phpPort);

    log_message(data: build_detection_report(app:"phpMyAdmin",
                                             version:ver,
                                             install:dir,
                                             cpe:cpe,
                                             concluded:phpmaVer[0],
                                             extra:info),
    port:phpPort);
  }
}

exit(0);
