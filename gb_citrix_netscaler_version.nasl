###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_version.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Citrix NetScaler Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105271");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2015-05-11 16:54:59 +0200 (Mon, 11 May 2015)");
 script_name("Citrix NetScaler Version Detection");

 script_summary("This script performs SSH based detection of Citrix NetScaler");

 script_tag(name:"qod_type", value:"package");

 script_summary("Checks for the presence of Citrix NetScaler");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("gather-package-list.nasl","netscaler_web_detect.nasl");
 script_mandatory_keys("citrix_netscaler/found");
 exit(0);
}


include("host_details.inc");

source = 'SSH';
location = 'ssh';

cpe = 'cpe:/a:citrix:netscaler';
vers = 'unknown';

system = get_kb_item("citrix_netscaler/system");

if( "NetScaler" >< system )
{
  ns = TRUE;
  version = eregmatch( string:system, pattern:"NetScaler NS([^:]+):");

  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    replace_kb_item( name:"citrix_netscaler/version", value:vers );
    cpe += ':' + vers;
  }

  _build = eregmatch( string:system, pattern:'Build ([0-9]+\\.[0-9]+)\\.([^,]+)' );

  if( ! isnull( _build[1] ) )
  {
    build = _build[1];
    replace_kb_item( name:"citrix_netscaler/build", value:build);
  }

  if( ! isnull( _build[2] ) )
  {
    if( _build[2] == 'e' )  replace_kb_item( name:"citrix_netscaler/enhanced_build", value:TRUE );
  }
} 
else
{
  if( ! web_version = get_kb_item( "citrix_netscaler/web/version" ) ) exit( 0 );

  ns = TRUE;
  location = 'http';
  source = 'HTTP';

  v = split( web_version, sep:".", keep:FALSE );
  if( max_index(v)  >= 4 )
  {
    vers = v[0] + '.' + v[1];
    replace_kb_item( name:"citrix_netscaler/version", value:vers );
    cpe += ':' + vers;

    build = v[2] + '.' + v[3];
    replace_kb_item( name:"citrix_netscaler/build", value:build);

    if( v[4] && v[4] == 'e' ) replace_kb_item( name:"citrix_netscaler/enhanced_build", value:TRUE );
  }
}

if( ns )
{
  register_product( cpe:cpe, location:location );

  report = 'Detected Citrix NetScaler (' + location + ')\n\n' +
           'Version: ' + vers + '\n';

  if( !isnull( build ) )
    report += 'Build:   ' + build + '\n';

  report += 'CPE:     ' + cpe;

  log_message( port:0, data:report );

  exit( 0 );
}

exit( 0 );


