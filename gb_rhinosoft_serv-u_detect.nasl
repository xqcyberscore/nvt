###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Serv-U Detection (FTP)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801117");
  script_version("2019-06-24T07:07:07+0000");
  script_tag(name:"last_modification", value:"2019-06-24 07:07:07 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SolarWinds Serv-U Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_mandatory_keys("ftp/serv-u/detected");

  script_tag(name:"summary", value:"Detection of SolarWinds Serv-U.

  This script performs FTP based detection of SolarWinds Serv-U.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# 220 Serv-U FTP Server v15.0 ready...
# 200 Name=Serv-U; Version=15.0.0.0; OS=Windows Server 2012; OSVer=6.2.9200; CaseSensitive=0;
#
# 220 Serv-U FTP Server v6.2 for WinSock ready...
if( ! banner || "Serv-U" >!< banner )
  exit( 0 );

# Response to CSID command (See get_ftp_banner() in ftp_func.inc)
vers = eregmatch( string:banner, pattern:"Name=Serv-U; Version=([^;]+);" );
if( ! isnull( vers[1] ) ) {
  set_kb_item( name:"solarwinds/servu/ftp/" + port + "/version", value:vers[1] );
  set_kb_item( name:"solarwinds/servu/ftp/" + port + "/concluded", value:banner );
} else {
  vers = eregmatch( pattern:"Serv-U FTP Server v([0-9.]+)", string:banner );
  if( ! isnull( vers[1] ) ) {
    set_kb_item( name:"solarwinds/servu/ftp/" + port + "/version", value:vers[1] );
    set_kb_item( name:"solarwinds/servu/ftp/" + port + "/concluded", value:banner );
  }
}

set_kb_item( name:"solarwinds/servu/detected", value:TRUE );
set_kb_item( name:"solarwinds/servu/ftp/port", value:port );

exit( 0 );