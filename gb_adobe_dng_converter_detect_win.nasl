###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_dng_converter_detect_win.nasl 7051 2017-09-04 11:38:56Z cfischer $
#
# Adobe DNG Converter Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809761");
  script_version("$Revision: 7051 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:38:56 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-12-15 15:01:50 +0530 (Thu, 15 Dec 2016)");
  script_name("Adobe DNG Converter Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"Detection of installed version of
  Adobe DNG Converter.

  The script runs a wmi query for 'Adobe DNG Converter.exe' and extracts the
  version information from query result.");

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

query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Adobe DNG Converter' + raw_string(0x22) +
        ' AND Extension =' + raw_string(0x22) + 'exe' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );
if( ! fileVer ) exit( 0 );

foreach ver( split( fileVer ) ) {
  if( ver =~ "adobe dng converter.exe" ) {
    info =  eregmatch( pattern:"(.*)\adobe\\adobe dng converter.exe.?([0-9.]+)", string:ver );
    if( info ) {
      version  = info[2];
      location = info[1];

      set_kb_item( name:"Adobe/DNG/Converter/Win/Version", value:version );

      ##Only 32-bit app is available
      ##Update CPE once available in NVD
      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:dng_converter:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:adobe:dng_converter";

      register_product( cpe:cpe, location:location );
      log_message( data:build_detection_report( app:"Adobe DNG Converter",
                                                version:version,
                                                install:location,
                                                cpe:cpe,
                                                concluded:version ) );
    }
  }
}

exit( 0 );
