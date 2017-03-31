###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_detect.nasl 4653 2016-12-01 11:41:20Z cfi $
#
# Dell Remote Access Controller Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103680");
  script_version("$Revision: 4653 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-01 12:41:20 +0100 (Thu, 01 Dec 2016) $");
  script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dell Remote Access Controller Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value :"Detection of Dell Remote Access Controller.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

urls = make_array();

urls['/cgi/lang/en/login.xsl'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/public/about.html'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';
urls['/cgi/about'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/Applications/dellUI/Strings/EN_about_hlp.htm'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';

info_url[4] = make_list('/cgi/about');
info_url_regex[4] = make_list('var s_build = "([^"]+)"');

info_url[5] = make_list('/cgi-bin/webcgi/about');
info_url_regex[5] = make_list('<FirmwareVersion>([^<]+)</FirmwareVersion>');

info_url[6] = make_list('/public/about.html','/Applications/dellUI/Strings/EN_about_hlp.htm');
info_url_regex[6] = make_list('Version ([^<]+)<br>','var fwVer = "([^"]+)";','Version ([0-9.]+)');

info_url[7] = make_list('/public/about.html');
info_url_regex[7] = make_list('var fwVer = "([^("]+)";');

info_url[8] = make_list('/public/about.html'); # untested
info_url_regex[8] = make_list('var fwVer = "([^("]+)";'); # untested

foreach url ( keys( urls ) )
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! buf ) continue;

  if( ! egrep( pattern:urls[url], string:buf ) ) continue;

  version = eregmatch( pattern:urls[url], string:buf );
  if( isnull( version[1] ) ) continue;

  set_kb_item(name:"dell_remote_access_controller/version", value:version[1]);

  cpe = 'cpe:/h:dell:remote_access_card:' + version[1];

  iv = int( version[1] );
  iv_urls = info_url[iv];

  if( iv_urls )
  {
    foreach iv_url ( iv_urls )
    {
      req = http_get( item:iv_url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( ! buf || "HTTP/1\.1 404" >< buf ) continue;

      foreach iur (info_url_regex[iv])
      {
        fw_version = eregmatch( pattern:iur, string:buf );
        if( ! isnull( fw_version[1] ) )
        {
          fw = fw_version[1];
          break;
        }
      }

      if( fw )
      {
        if("(Build" >< fw )
        {
          f = eregmatch( pattern:'^([0-9.]+)\\(Build ([0-9]+)\\)', string:fw );
          if( ! isnull( f[1] ) ) fw = f[1];
          if( ! isnull( f[2] ) )
            set_kb_item(name:"dell_remote_access_controller/fw_build", value:f[2]);
        }

        set_kb_item(name:"dell_remote_access_controller/fw_version", value:fw);

        cpe_fw = str_replace(string:tolower(fw), find:" ", replace:"_");
        cpe_fw = str_replace(string:tolower(cpe_fw), find:"(", replace:"_");
        cpe_fw = str_replace(string:tolower(cpe_fw), find:")", replace:"");
        cpe_fw = str_replace(string:tolower(cpe_fw), find:"__", replace:"_");

        cpe = cpe + ':firmware_' + cpe_fw;
        break;
      }
    }
  }

  if( cpe )
  {
     register_product(cpe:cpe, location:url, port:port);
     log_message(data: build_detection_report(app:"Dell Remote Access Controller", version:fw, install:url, cpe:cpe, concluded: version[0]),
                 port:port);
     exit( 0 );
  }
}

exit( 0 );

