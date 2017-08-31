###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Python_detection.nasl 6701 2017-07-12 13:04:06Z cfischer $
#
# Python Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107020");
  script_version("$Revision: 6701 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 15:04:06 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-07-04 19:31:49 +0200 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Python Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Python/banner");

  script_tag(name:"summary", value:"Detection of installed version of Python

  The script detects the version of Python on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

# Check for Python Version 
if( ve = egrep( pattern:'Server[^\r\n]+(C)?Python/[0-9]+', string:banner ) ) {

  vers = "unknown";

  ### try to get version
  version = eregmatch( string:ve, pattern:"C?Python/([0-9.]+)", icase:TRUE );

  if( ! isnull( version[0] ) ) {
    concluded = chomp( version[0] );
    vers = version[1];
  }

  set_kb_item( name:"www/" + port + "/Python", value:vers );
  set_kb_item( name:"pyVer/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:python:python:" );

  if( ! cpe )
    cpe = "cpe:/a:python:python";

  ## Register Product and Build Report
  register_product( cpe:cpe, location:port + '/tcp', port:port );
  log_message( data:build_detection_report( app:"Python",
                                            version:vers,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
