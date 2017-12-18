###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_detect.nasl 8143 2017-12-15 13:11:11Z cfischer $
#
# OpenSSL Remote Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806723");
  script_version("$Revision: 8143 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:11:11 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-11-24 16:05:56 +0530 (Tue, 24 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Remote Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  OpenSSL.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("OpenSSL/banner");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
### Code Starts Here
##

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! ports = get_kb_list( "Services/www" ) ) exit( 0 );

function version_already_detected( v, k )
{
  if( ! v ) return;

  foreach vers ( k )
    if( v == vers ) return TRUE;

  return;
}

ad = make_list();

##Get OpenSSL Port
foreach sslPort ( ports )
{
  if( ! get_port_state( sslPort ) ) continue;

  cpe = "";
  banner = "";
  sslVer = "";

  ##Send Request and Receive Response
  banner = get_http_banner(port:sslPort);

  #Confirm application
  if(banner && "OpenSSL/" >< banner)
  {
    ##Getting version from the respone
    version = eregmatch(pattern: 'OpenSSL/([0-9]+[^ \r\n]+)', string: banner);
    if(!version){
      sslVer = "Unknown";
    } else{
      sslVer = version[1];
    }

    ## Set the KB
    set_kb_item(name:"www/" + sslPort + "/", value:sslVer);
    set_kb_item(name:"OpenSSL/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:sslVer, exp:"^([0-9a-z.-]+)", base:"cpe:/a:openssl:openssl:");
    if(isnull(cpe))
      cpe = "cpe:/a:openssl:openssl";

    if( ! version_already_detected( v:sslVer, k:ad ) ) # register any version only once
    {
      ad = make_list( ad, sslVer );
      register_product(cpe:cpe, location:"/", port:sslPort);
      log_message(data: build_detection_report(app:"OpenSSL",
                                               version:sslVer,
                                               install:"/",
                                               cpe:cpe,
                                               concluded:'"' + version[0] + '" at port ' + sslPort),
                                               port:sslPort);
    }
  }
}

exit( 0 );
