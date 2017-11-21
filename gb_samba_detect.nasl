###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_detect.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Samba Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Modified by: Sujit Ghosal (sghosal@secpod.com)
# Date: 8th May 2009
# Changes: Changed the command from smbd to smbclient and Modified Regex
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
# Revised to comply with Change Request #57.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800403");
  script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Samba Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  tag_summary = "Detection of installed version of Samba.

  The script logs in via ssh, searches for executable 'smbd' and
  queries the found executables via command line option '-V'.";

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit(-1);

smbName = find_file( file_name:"smbd", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock );

foreach executableFile( smbName ) {

  executableFile = chomp( executableFile );

  smbVer = get_bin_version( full_prog_name:executableFile, version_argv:"-V",
                            ver_pattern:"Version (.*)", sock:sock );

  smbVer = split( smbVer[1], "\n", keep:0 );

  if( ! isnull( smbVer[0] ) ) {
    set_kb_item( name:"Samba/Version", value:smbVer[0] );
    set_kb_item( name:"samba/detected", value:TRUE );

    cpe = build_cpe( value:smbVer[0], exp:"([0-9.]+)", base:"cpe:/a:samba:samba:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:samba:samba';

    register_product( cpe:cpe, location:executableFile );

    log_message( data:build_detection_report( app:"Samba",
                                              version:smbVer[0],
                                              install:executableFile,
                                              cpe:cpe,
                                              concluded:smbVer[max_index(smbVer)-1] ) );
  }
}

ssh_close_connection();

exit( 0 );
