###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_pdf_toolkit_detect.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
#
# Foxit PDF Toolkit Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810522");
  script_version("$Revision: 11356 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-25 15:52:27 +0530 (Wed, 25 Jan 2017)");
  script_name("Foxit PDF Toolkit Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl");

  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"Detects the installed version of
  Foxit PDF Toolkit.

  The script logs in via smb and gets the version from Foxit PDF Toolkit
  file 'fhtml2pdf.exe'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );
domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

## WMI query to grep the file version
query = 'Select Manufacturer, Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'fhtml2pdf' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'exe' + raw_string(0x22);
appConfirm = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );

if( "Foxit Software Inc" >< appConfirm ) {

  version = eregmatch( pattern:"\fhtml2pdf.exe.?([0-9.]+)", string:appConfirm );
  if( version[1] ) {
    path = eregmatch( pattern:"Foxit Software Inc\|(.*)\|([0-9.]+)", string:appConfirm );
    if( path ) {
      path = path[1];
    } else {
      path = "Couldn find the install location from registry";
    }

    set_kb_item( name:"foxit/pdf_toolkit/win/ver", value:version[1] );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:foxit_pdf_toolkit:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:foxitsoftware:foxit_pdf_toolkit";

    register_product( cpe:cpe, location:path );

    log_message( data:build_detection_report( app:"Foxit PDF Toolkit",
                                              version:version[1],
                                              install:path,
                                              cpe:cpe,
                                              concluded:version[1] ) );
  }
}

exit( 0 );
