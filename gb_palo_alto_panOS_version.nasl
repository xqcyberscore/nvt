###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_palo_alto_panOS_version.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Palo Alto PAN-OS Version Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105263");
  script_version("$Revision: 8078 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-04-22 14:02:11 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Palo Alto PAN-OS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "gb_palo_alto_version_api.nasl");
  script_mandatory_keys("panOS/system");

  script_tag(name:"summary", value:"This script detect the PAN-OS Version through SSH or XML-API");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}


include("host_details.inc");

if( ! system = get_kb_item( "panOS/system" ) ) exit( 0 );
set_kb_item( name:"palo_alto_pan_os/installed", value:TRUE );

detected_by = get_kb_item( "panOS/detected_by" );

if( detected_by == "XML-API" )
{
  vpattern = '<sw-version>([^<]+)</sw-version>';
  mpattern = '<model>([^<]+)</model>';
}
else if( detected_by == "SSH" )
{
  vpattern = 'sw-version: ([^ \r\n]+)';
  mpattern = 'model: ([^ \r\n]+)';
}
else
 exit( 0 );

app = 'Palo Alto PAN-OS';
vers = 'unknown';
cpe = 'cpe:/o:paloaltonetworks:pan-os';

version = eregmatch( pattern:vpattern, string:system );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  if( "-h" >< vers )
  {
    v_h = split( vers, sep:"-h", keep:FALSE );
    vers = v_h[0];
    hotfix = v_h[1];
  }
  set_kb_item( name:"palo_alto_pan_os/version", value:vers );
  cpe += ':' + vers;
}

rep_vers = vers;

if( hotfix )
{
  set_kb_item( name:"palo_alto_pan_os/hotfix", value:hotfix );
  rep_vers = vers + '-h' + hotfix;
}

mod = eregmatch( pattern:mpattern, string:system );
if( ! isnull( mod[1] ) )
{
  model = mod[1];
  set_kb_item( name:"palo_alto_pan_os/model", value:model);
  app += ' (' + model + ')';
}

register_product( cpe:cpe, location:detected_by );

register_and_report_os( os:"PAN-OS (" + vers + ")", cpe:cpe, banner_type:detected_by, desc:"Palo Alto PAN-OS Version Detection", runs_key:"unixoide" );

log_message( data: build_detection_report( app:app,
                                           version:rep_vers,
                                           install:detected_by,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

exit( 0 );

